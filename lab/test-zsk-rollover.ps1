param(
    [ValidateRange(0, 60)]
    [int]$ObservationDelaySeconds = 2
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$baseCompose = Join-Path $PSScriptRoot 'docker-compose.yml'
$overrideCompose = Join-Path $repoRoot 'scenarios\zsk-rollover\docker-compose.yml'
$baseArgs = @('-p', 'lab', '-f', $baseCompose)
$zskArgs = @('-p', 'lab', '-f', $baseCompose, '-f', $overrideCompose)
$scenarioActive = $false
Push-Location $repoRoot

function Assert-ExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE" }
}

function Invoke-Zsk([string]$Command) {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = docker compose @zskArgs run --rm --no-deps zsk-rollover $Command
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    $output | Out-Host
    if ($exitCode -ne 0) { throw "zsk-rollover $Command failed with exit code $exitCode" }
    return $output
}

function Get-ParentDs {
    $value = (docker compose @baseArgs exec -T root dig '@172.30.0.11' victim.test. DS +short +nosplit | Out-String).Trim()
    Assert-ExitCode 'query parent DS'
    return $value
}

function Get-ParentNs {
    $value = (docker compose @baseArgs exec -T root dig '@172.30.0.11' victim.test. NS +noall +answer +authority | Out-String).Trim()
    Assert-ExitCode 'query parent NS'
    if ($value -notmatch '\sNS\s+(\S+)\s*$') { throw "Could not parse parent NS: $value" }
    return $Matches[1]
}

function Get-KskRecord {
    $value = (docker compose @baseArgs exec -T root dig '@172.30.0.12' victim.test. DNSKEY +noall +answer +nosplit | Where-Object { $_ -match '\sDNSKEY\s+257\s+3\s+13\s+' } | Out-String).Trim()
    Assert-ExitCode 'query provider KSK DNSKEY'
    if (-not $value) { throw 'Provider did not publish a flag-257 DNSKEY' }
    return ($value -replace '^\S+\s+\d+\s+IN\s+DNSKEY\s+', '') -replace '\s+', ' '
}

function Get-DnskeyCounts {
    $lines = docker compose @baseArgs exec -T root dig '@172.30.0.12' victim.test. DNSKEY +short
    Assert-ExitCode 'query provider DNSKEY roles'
    return @{
        Ksk = @($lines | Where-Object { $_ -match '^257\s+3\s+13\s+' }).Count
        Zsk = @($lines | Where-Object { $_ -match '^256\s+3\s+13\s+' }).Count
    }
}

function Get-RrsigTags([string]$Type) {
    $lines = docker compose @baseArgs exec -T root dig '@172.30.0.12' victim.test. $Type +dnssec +noall +answer
    Assert-ExitCode "query RRSIG($Type)"
    return @($lines | ForEach-Object {
        if ($_ -match "\sRRSIG\s+$Type\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+") { [int]$Matches[1] }
    } | Sort-Object -Unique)
}

function Assert-Invariants([string]$Phase) {
    if ((Get-ParentDs) -ne $script:baselineDs) { throw "Parent DS changed during $Phase" }
    if ((Get-ParentNs) -ne $script:baselineNs) { throw "Parent NS changed during $Phase" }
    if ((Get-KskRecord) -ne $script:baselineKsk) { throw "KSK public identity changed during $Phase" }

    docker compose @baseArgs exec -T unbound unbound-control flush_zone victim.test. | Out-Host
    Assert-ExitCode "flush Unbound during $Phase"
    $answer = docker compose @baseArgs exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String
    Assert-ExitCode "query Unbound during $Phase"
    if ($answer -notmatch 'status: NOERROR' -or $answer -notmatch 'flags:.*\bad\b' -or $answer -notmatch 'A\s+192\.0\.2\.10') {
        throw "Unbound did not return 192.0.2.10 with AD=true during $Phase"
    }
    Write-Host "PASS: KSK, parent DS/NS, provider address, and AD=true during $Phase."
}

function Observe([string]$Phase) {
    Write-Host "OBSERVABLE PHASE: $Phase"
    if ($ObservationDelaySeconds -gt 0) { Start-Sleep -Seconds $ObservationDelaySeconds }
}

try {
    docker compose @baseArgs up -d | Out-Host
    Assert-ExitCode 'start base lab'
    & (Join-Path $PSScriptRoot 'reset-zsk-rollover.ps1')

    $script:baselineDs = Get-ParentDs
    $script:baselineNs = Get-ParentNs
    $script:baselineKsk = Get-KskRecord
    $baselineCounts = Get-DnskeyCounts
    if ($baselineCounts.Ksk -ne 1 -or $baselineCounts.Zsk -ne 0) {
        throw 'Expected the shared baseline to contain one CSK and no separate ZSK'
    }
    Assert-Invariants 'CSK baseline'
    Observe 'csk-baseline'

    docker compose @zskArgs config --quiet
    Assert-ExitCode 'validate Scenario 1 Compose override'
    docker compose @zskArgs run --rm --no-deps zsk-prepare | Out-Host
    Assert-ExitCode 'prepare isolated split-key state'

    docker compose @zskArgs up -d --no-deps --force-recreate provider | Out-Host
    Assert-ExitCode 'activate isolated split-key provider'
    $scenarioActive = $true

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $counts = Get-DnskeyCounts
            if ($counts.Ksk -eq 1 -and $counts.Zsk -eq 1) { $ready = $true; break }
        }
        catch {
            # The provider can briefly refuse queries while named starts and
            # opens its inline-signing journals. Retry within the bound.
        }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Split-key provider did not become ready' }

    Invoke-Zsk 'establish-baseline' | Out-Null
    $splitCounts = Get-DnskeyCounts
    if ($splitCounts.Ksk -ne 1 -or $splitCounts.Zsk -ne 1) { throw 'Split baseline has incorrect DNSKEY roles' }
    Assert-Invariants 'split-key baseline'
    Observe 'split-baseline'

    $beginOutput = Invoke-Zsk 'begin'
    $oldLine = @($beginOutput | Where-Object { $_ -match '^OLD_ZSK_TAG=\d+$' } | Select-Object -Last 1)[0]
    $newLine = @($beginOutput | Where-Object { $_ -match '^NEW_ZSK_TAG=\d+$' } | Select-Object -Last 1)[0]
    $oldZsk = [int]($oldLine -replace '^OLD_ZSK_TAG=', '')
    $newZsk = [int]($newLine -replace '^NEW_ZSK_TAG=', '')
    if ($oldZsk -eq $newZsk) { throw 'Successor ZSK is not independent' }
    $publishedCounts = Get-DnskeyCounts
    if ($publishedCounts.Ksk -ne 1 -or $publishedCounts.Zsk -ne 2) { throw 'New-ZSK publication did not produce two ZSKs' }
    Assert-Invariants 'new ZSK publication'
    Observe 'new-zsk-published'

    Invoke-Zsk 'activate' | Out-Null
    $overlapSigners = Get-RrsigTags 'A'
    if (-not ($overlapSigners -contains $oldZsk) -or -not ($overlapSigners -contains $newZsk)) {
        throw 'Apex A RRset does not have the expected old/new ZSK signature overlap'
    }
    Assert-Invariants 'ZSK signature transition'
    Observe 'zsk-signature-overlap'

    Invoke-Zsk 'retire' | Out-Null
    $retiredSigners = Get-RrsigTags 'A'
    if ($retiredSigners -contains $oldZsk -or -not ($retiredSigners -contains $newZsk)) {
        throw 'Ordinary apex signatures did not transition exclusively to the successor ZSK'
    }
    Assert-Invariants 'old ZSK retirement and cache-safety hold'
    Observe 'old-zsk-retired'

    Invoke-Zsk 'complete' | Out-Null
    $finalCounts = Get-DnskeyCounts
    if ($finalCounts.Ksk -ne 1 -or $finalCounts.Zsk -ne 1) { throw 'Final DNSKEY RRset is not one KSK plus one ZSK' }
    $finalSigners = Get-RrsigTags 'A'
    if ($finalSigners -contains $oldZsk -or -not ($finalSigners -contains $newZsk)) {
        throw 'Final ordinary RRset is not signed exclusively by the successor ZSK'
    }
    Assert-Invariants 'completed ZSK rollover'
    Observe 'complete'

    docker compose @baseArgs exec -T root sh /opt/lab/test-dnssec.sh | Out-Host
    Assert-ExitCode 'DNSSEC baseline regression in split-key state'
    Write-Host "PASS: genuine ZSK-only rollover completed: $oldZsk -> $newZsk; KSK and parent delegation unchanged."
}
finally {
    if ($scenarioActive) {
        & (Join-Path $PSScriptRoot 'reset-zsk-rollover.ps1')
    }
    Pop-Location
}

Write-Host 'All requested ZSK rollover checks passed.'
