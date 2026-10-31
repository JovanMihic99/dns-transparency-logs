param(
    [ValidateRange(0, 60)]
    [int]$ObservationDelaySeconds = 2
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$composeFile = Join-Path $repoRoot 'lab\docker-compose.yml'
Push-Location $repoRoot

function Assert-ExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE" }
}

function Invoke-Rollover([string]$Command) {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = docker compose -f $composeFile run --rm --no-deps ksk-rollover $Command
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    $output | Out-Host
    if ($exitCode -ne 0) { throw "ksk-rollover $Command failed with exit code $exitCode" }
    return $output
}

function Invoke-CdsSync([string]$Command) {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = docker compose -f $composeFile run --rm --no-deps cds-sync $Command
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    $output | Out-Host
    if ($exitCode -ne 0) { throw "cds-sync $Command failed with exit code $exitCode" }
    return $output
}

function Get-NumericValue($Output, [string]$Prefix) {
    $line = @($Output | Where-Object { $_ -match "^$Prefix\d+$" } | Select-Object -Last 1)
    if ($line.Count -ne 1) { throw "Could not read $Prefix from rollover output" }
    return [int]($line[0] -replace "^$Prefix", '')
}

function Get-RrTags([string]$Server, [string]$Type) {
    $raw = docker compose -f $composeFile exec -T root dig "@$Server" victim.test. $Type +short
    Assert-ExitCode "query $Type from $Server"
    return @($raw | ForEach-Object {
        if ($_ -match '^\s*(\d+)\s+13\s+2\s+') { [int]$Matches[1] }
    } | Sort-Object -Unique)
}

function Get-ParentNs {
    $raw = (docker compose -f $composeFile exec -T root dig '@172.30.0.11' victim.test. NS +noall +answer +authority | Out-String).Trim()
    Assert-ExitCode 'query parent NS'
    if ($raw -notmatch '\sNS\s+(\S+)\s*$') { throw "Could not parse parent NS from: $raw" }
    return $Matches[1]
}

function Assert-Tags([int[]]$Actual, [int[]]$Expected, [string]$Label) {
    $actualText = (@($Actual | Sort-Object) -join ',')
    $expectedText = (@($Expected | Sort-Object) -join ',')
    if ($actualText -ne $expectedText) { throw "$Label expected [$expectedText], found [$actualText]" }
    Write-Host "PASS: $Label has key tag(s) $actualText."
}

function Assert-Validated([string]$Phase) {
    docker compose -f $composeFile exec -T unbound unbound-control flush_zone victim.test. | Out-Host
    Assert-ExitCode "flush Unbound during $Phase"
    $answer = docker compose -f $composeFile exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String
    Assert-ExitCode "query Unbound during $Phase"
    if ($answer -notmatch 'status: NOERROR' -or
        $answer -notmatch 'flags:.*\bad\b' -or
        $answer -notmatch 'A\s+192\.0\.2\.10') {
        throw "Unbound did not return 192.0.2.10 with AD=true during $Phase"
    }
    Write-Host "PASS: AD=true and provider address during $Phase."
}

function Observe([string]$Phase) {
    Write-Host "OBSERVABLE PHASE: $Phase"
    if ($ObservationDelaySeconds -gt 0) { Start-Sleep -Seconds $ObservationDelaySeconds }
}

try {
    docker compose -f $composeFile build cds-sync | Out-Host
    Assert-ExitCode 'build CDS synchronizer'
    docker compose -f $composeFile up -d | Out-Host
    Assert-ExitCode 'start lab'

    & (Join-Path $repoRoot 'lab\reset-cds-rollover.ps1')
    Assert-ExitCode 'establish stable CDS rollover baseline'
    $baselineNs = Get-ParentNs
    if ($baselineNs -ne 'ns.victim.test.') { throw "Unexpected baseline parent NS: $baselineNs" }
    Assert-Validated 'stable baseline'
    Invoke-CdsSync 'validate' | Out-Null
    Observe 'baseline'

    $begin = Invoke-Rollover 'begin'
    $oldTag = Get-NumericValue $begin 'OLD_TAG='
    $newTag = Get-NumericValue $begin 'NEW_TAG='
    if ($oldTag -eq $newTag) { throw 'BIND did not generate an independent successor key' }
    $dnskeys = docker compose -f $composeFile exec -T root dig '@172.30.0.12' victim.test. DNSKEY +short
    Assert-ExitCode 'query child DNSKEY publication'
    if (@($dnskeys | Where-Object { $_ -match '^257\s+3\s+13\s+' }).Count -ne 2) {
        throw 'Expected old and new child DNSKEYs after begin'
    }
    Assert-Validated 'new KSK publication'
    Observe 'new-key-published'

    Invoke-Rollover 'publish-cds-both' | Out-Null
    Assert-Tags (Get-RrTags '172.30.0.12' 'CDS') @($oldTag, $newTag) 'signed child CDS overlap'
    Invoke-CdsSync 'validate' | Out-Null
    Assert-Validated 'signed old+new CDS publication'
    Observe 'cds-old-and-new'

    Invoke-CdsSync 'sync' | Out-Null
    Assert-Tags (Get-RrTags '172.30.0.11' 'DS') @($oldTag, $newTag) 'parent double-DS overlap'
    if ((Get-ParentNs) -ne $baselineNs) { throw 'Parent NS delegation changed during CDS synchronization' }
    Assert-Validated 'CDS-driven parent double-DS update'
    Observe 'parent-double-ds'

    $idempotent = Invoke-CdsSync 'sync'
    if (-not ($idempotent -match '^action=noop$')) { throw 'Second unchanged CDS sync was not idempotent' }
    Write-Host 'PASS: unchanged CDS sync was an idempotent no-op.'

    Invoke-Rollover 'acknowledge-published' | Out-Null
    Assert-Validated 'new DS acknowledgement and key activation'
    Observe 'new-key-active'

    Invoke-Rollover 'publish-cds-new' | Out-Null
    Assert-Tags (Get-RrTags '172.30.0.12' 'CDS') @($newTag) 'new-only child CDS'
    Invoke-CdsSync 'validate' | Out-Null
    Observe 'cds-new-only'

    Invoke-CdsSync 'sync' | Out-Null
    Assert-Tags (Get-RrTags '172.30.0.11' 'DS') @($newTag) 'new-only parent DS'
    if ((Get-ParentNs) -ne $baselineNs) { throw 'Parent NS delegation changed when withdrawing old DS' }
    Assert-Validated 'CDS-driven old DS withdrawal'
    Observe 'old-ds-withdrawn'

    $beforeTamper = (Get-RrTags '172.30.0.11' 'DS') -join ','
    Invoke-CdsSync 'verify-tampered' | Out-Null
    $afterTamper = (Get-RrTags '172.30.0.11' 'DS') -join ','
    if ($beforeTamper -ne $afterTamper) { throw 'Tampered CDS test changed the parent DS' }
    Write-Host 'PASS: tampered CDS was rejected before UPDATE and parent DS was unchanged.'

    Invoke-Rollover 'acknowledge-withdrawn' | Out-Null
    Assert-Tags (Get-RrTags '172.30.0.11' 'DS') @($newTag) 'final parent DS'
    $finalDnskeys = docker compose -f $composeFile exec -T root dig '@172.30.0.12' victim.test. DNSKEY +short
    Assert-ExitCode 'query final child DNSKEY state'
    if (@($finalDnskeys | Where-Object { $_ -match '^257\s+3\s+13\s+' }).Count -ne 1) {
        throw 'Final child DNSKEY RRset is not new-key-only'
    }
    Assert-Validated 'completed CDS rollover'
    Observe 'complete'

    docker compose -f $composeFile exec -T root sh /opt/lab/test-dnssec.sh | Out-Host
    Assert-ExitCode 'DNSSEC baseline regression'
    Invoke-Rollover 'reconcile' | Out-Null
    Write-Host "PASS: legitimate CDS-driven rollover completed: $oldTag -> $newTag."
}
finally {
    Pop-Location
}
