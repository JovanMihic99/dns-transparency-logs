$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:ComposeFile = Join-Path $script:RepoRoot 'lab\docker-compose.yml'
$script:ComposeArgs = @('-p', 'lab', '-f', $script:ComposeFile)
$script:Zone = 'victim.test.'
$script:Provider = '172.30.0.12'
$script:Tld = '172.30.0.11'
$script:Unbound = '172.30.0.14'
$script:PolicyPropagationMarginSeconds = 5

function Assert-ExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE" }
}

function Invoke-Rollover([string]$Command) {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = docker compose @script:ComposeArgs run --rm --no-deps ksk-rollover $Command
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    $output | Out-Host
    if ($exitCode -ne 0) { throw "ksk-rollover $Command failed with exit code $exitCode" }
    return @($output)
}

function Invoke-Registrar([string[]]$Arguments) {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = docker compose @script:ComposeArgs run --rm --no-deps registrar @Arguments
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    $output | Out-Host
    if ($exitCode -ne 0) { throw "registrar $($Arguments -join ' ') failed with exit code $exitCode" }
    return @($output)
}

function Get-SortedUniqueIntegers($Values) {
    return @($Values | ForEach-Object { [int]$_ } | Sort-Object -Unique)
}

function Get-CanonicalDsFromLines($Lines) {
    $records = @()
    foreach ($line in $Lines) {
        if ($line -match '\sIN\s+DS\s+(\d+)\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f]+)') {
            $records += [pscustomobject]@{
                Tag = [int]$Matches[1]
                Algorithm = [int]$Matches[2]
                DigestType = [int]$Matches[3]
                Digest = $Matches[4].ToUpperInvariant()
                Canonical = "$($Matches[1]) $($Matches[2]) $($Matches[3]) $($Matches[4].ToUpperInvariant())"
            }
        }
    }
    return @($records | Sort-Object Canonical -Unique)
}

function Assert-AdResponse([string[]]$Lines, [string]$Label) {
    $text = $Lines | Out-String
    if ($text -notmatch 'status:\s+NOERROR' -or $text -notmatch 'flags:.*\bad\b') {
        throw "$Label was not authenticated by Unbound (NOERROR and AD=true required)"
    }
}

function Get-ChildSnapshot {
    docker compose @script:ComposeArgs exec -T unbound unbound-control flush_zone $script:Zone | Out-Null
    Assert-ExitCode 'flush Unbound before authenticated child DNSKEY query'
    $answer = @(docker compose @script:ComposeArgs exec -T root dig "@$script:Unbound" $script:Zone DNSKEY +dnssec +noall +comments +answer +nosplit)
    Assert-ExitCode 'query authenticated child DNSKEY'
    Assert-AdResponse $answer 'Child DNSKEY RRset'

    $dnskeyLines = @($answer | Where-Object { $_ -match '\sDNSKEY\s+257\s+3\s+13\s+' })
    if ($dnskeyLines.Count -eq 0) { throw 'Authenticated child response contains no ECDSAP256SHA256 flag-257 DNSKEY' }

    $ttlValues = @($dnskeyLines | ForEach-Object {
        if ($_ -match '^\S+\s+(\d+)\s+IN\s+DNSKEY') { [int]$Matches[1] }
    })
    if ($ttlValues.Count -eq 0) { throw 'Could not determine authenticated DNSKEY TTL' }

    $signers = @(Get-SortedUniqueIntegers @($answer | ForEach-Object {
        if ($_ -match '\sRRSIG\s+DNSKEY\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+') { $Matches[1] }
    }))
    if ($signers.Count -eq 0) { throw 'Authenticated child DNSKEY response contains no DNSKEY RRSIG signer' }

    $derivedLines = @(docker compose @script:ComposeArgs exec -T root sh -c "dig '@$script:Unbound' '$script:Zone' DNSKEY +dnssec +noall +answer +nosplit | dnssec-dsfromkey -2 -f - '$script:Zone'")
    Assert-ExitCode 'derive DS from authenticated child DNSKEY'
    $derived = @(Get-CanonicalDsFromLines $derivedLines)
    if ($derived.Count -ne $dnskeyLines.Count) {
        throw "Derived DS count $($derived.Count) does not match authenticated SEP DNSKEY count $($dnskeyLines.Count)"
    }

    return [pscustomobject]@{
        Tags = @(Get-SortedUniqueIntegers @($derived | ForEach-Object { $_.Tag }))
        DerivedDs = $derived
        SignerTags = $signers
        Ttl = [int](($ttlValues | Measure-Object -Maximum).Maximum)
        Answer = $answer
    }
}

function Get-ParentSnapshot {
    $direct = @(docker compose @script:ComposeArgs exec -T root dig "@$script:Tld" $script:Zone DS +dnssec +noall +answer +nosplit)
    Assert-ExitCode 'query authoritative parent DS'
    $records = @(Get-CanonicalDsFromLines $direct)
    if ($records.Count -eq 0) { throw 'Parent publishes no DS records' }
    if (-not ($direct -match '\sRRSIG\s+DS\s+')) { throw 'Parent DS RRset has no RRSIG' }

    $ttlValues = @($direct | ForEach-Object {
        if ($_ -match '^\S+\s+(\d+)\s+IN\s+DS\s+') { [int]$Matches[1] }
    })
    if ($ttlValues.Count -eq 0) { throw 'Could not determine parent DS TTL' }

    docker compose @script:ComposeArgs exec -T unbound unbound-control flush_zone $script:Zone | Out-Null
    Assert-ExitCode 'flush Unbound before authenticated parent DS query'
    $validated = @(docker compose @script:ComposeArgs exec -T root dig "@$script:Unbound" $script:Zone DS +dnssec +noall +comments +answer +nosplit)
    Assert-ExitCode 'query authenticated parent DS'
    Assert-AdResponse $validated 'Parent DS RRset'
    $validatedRecords = @(Get-CanonicalDsFromLines $validated)
    if ((@($records.Canonical) -join '|') -ne (@($validatedRecords.Canonical) -join '|')) {
        throw 'Authoritative parent DS and Unbound-authenticated parent DS differ'
    }

    $nsAnswer = @(docker compose @script:ComposeArgs exec -T root dig "@$script:Tld" $script:Zone NS +noall +answer +authority)
    Assert-ExitCode 'query parent NS delegation'
    $nameservers = @($nsAnswer | ForEach-Object {
        if ($_ -match '\sNS\s+(\S+)\s*$') { $Matches[1].ToLowerInvariant() }
    } | Sort-Object -Unique)

    return [pscustomobject]@{
        Tags = @(Get-SortedUniqueIntegers @($records | ForEach-Object { $_.Tag }))
        Records = $records
        Ttl = [int](($ttlValues | Measure-Object -Maximum).Maximum)
        Nameservers = $nameservers
        Answer = $direct
    }
}

function Get-BindStatus {
    $lines = @(docker compose @script:ComposeArgs exec -T provider rndc -s $script:Provider -p 953 -k /opt/lab/rollover-control.key dnssec -status $script:Zone)
    Assert-ExitCode 'query BIND DNSSEC key state'
    return ($lines | Out-String)
}

function Get-BindKeyBlock([int]$Tag) {
    $status = Get-BindStatus
    $match = [regex]::Match($status, "(?ms)^key:\s+$Tag\b.*?(?=^key:\s+\d+\b|\z)")
    if ($match.Success) { return $match.Value }

    # BIND 9.18 can publish a newly generated KASP key before rndc dnssec
    # -status includes its block. The persistent .state file is authoritative
    # BIND state and lets us distinguish rumoured publication/key-signing from
    # later omnipresent activation. Actual RRSIGs are checked separately.
    $statePath = '/var/lib/bind/keys/Kvictim.test.+013+{0:D5}.state' -f $Tag
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $stateLines = @(docker compose @script:ComposeArgs exec -T provider sh -c "test -s '$statePath' && cat '$statePath'" 2>$null)
    $stateExit = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    if ($stateExit -ne 0 -or $stateLines.Count -eq 0) {
        throw "BIND exposes neither rndc status nor persistent key state for $Tag"
    }
    $state = $stateLines | Out-String
    $dnskeyState = if ($state -match '(?m)^DNSKEYState:\s+(\S+)') { $Matches[1] } else { throw "Key $Tag state lacks DNSKEYState" }
    $krrsigState = if ($state -match '(?m)^KRRSIGState:\s+(\S+)') { $Matches[1] } else { throw "Key $Tag state lacks KRRSIGState" }
    $zrrsigState = if ($state -match '(?m)^ZRRSIGState:\s+(\S+)') { $Matches[1] } else { throw "Key $Tag state lacks ZRRSIGState" }
    $dsState = if ($state -match '(?m)^DSState:\s+(\S+)') { $Matches[1] } else { throw "Key $Tag state lacks DSState" }
    $goalState = if ($state -match '(?m)^GoalState:\s+(\S+)') { $Matches[1] } else { throw "Key $Tag state lacks GoalState" }
    $visibleStates = @('rumoured', 'omnipresent')
    $published = if ($visibleStates -contains $dnskeyState) { 'yes' } else { 'no' }
    $keySigning = if ($visibleStates -contains $krrsigState) { 'yes' } else { 'no' }
    $zoneSigning = if ($visibleStates -contains $zrrsigState) { 'yes' } else { 'no' }
    return @"
key: $Tag (persistent KASP state fallback)
  published:      $published
  key signing:    $keySigning
  zone signing:   $zoneSigning
  - goal:           $goalState
  - dnskey:         $dnskeyState
  - ds:             $dsState
  - zone rrsig:     $zrrsigState
  - key rrsig:      $krrsigState
"@
}

function Assert-BindKeyState(
    [int]$Tag,
    [ValidateSet('yes','no','either')][string]$Published = 'either',
    [ValidateSet('yes','no','either')][string]$KeySigning = 'either',
    [ValidateSet('yes','no','either')][string]$ZoneSigning = 'either',
    [string]$Goal = ''
) {
    $block = Get-BindKeyBlock $Tag
    if ($Published -ne 'either' -and $block -notmatch "(?m)^\s*published:\s+$Published\b") {
        throw "BIND key $Tag published state is not '$Published'"
    }
    if ($KeySigning -ne 'either' -and $block -notmatch "(?m)^\s*key signing:\s+$KeySigning\b") {
        throw "BIND key $Tag key-signing state is not '$KeySigning'"
    }
    if ($ZoneSigning -ne 'either' -and $block -notmatch "(?m)^\s*zone signing:\s+$ZoneSigning\b") {
        throw "BIND key $Tag zone-signing state is not '$ZoneSigning'"
    }
    if ($Goal -and $block -notmatch "(?m)^\s*- goal:\s+$Goal\b") {
        throw "BIND key $Tag goal is not '$Goal'"
    }
    return $block
}

function Assert-StableBindKey([int]$Tag) {
    $block = Assert-BindKeyState -Tag $Tag -Published yes -KeySigning yes -ZoneSigning yes -Goal omnipresent
    if ($block -notmatch 'No rollover scheduled') { throw "BIND key $Tag still has a rollover scheduled" }
    if ($block -notmatch '(?m)^\s*- ds:\s+omnipresent\b') { throw "BIND key $Tag DS state is not omnipresent" }
}

function Assert-ValidatedAddress([string]$Phase) {
    docker compose @script:ComposeArgs exec -T unbound unbound-control flush_zone $script:Zone | Out-Host
    Assert-ExitCode "flush Unbound during $Phase"
    $answer = @(docker compose @script:ComposeArgs exec -T root dig "@$script:Unbound" www.victim.test. A +dnssec +noall +comments +answer)
    Assert-ExitCode "query Unbound during $Phase"
    Assert-AdResponse $answer "Provider A response during $Phase"
    if (($answer | Out-String) -notmatch 'A\s+192\.0\.2\.10') {
        throw "Provider address changed during $Phase"
    }
}

function Assert-Tags([int[]]$Actual, [int[]]$Expected, [string]$Label) {
    $actualText = (@($Actual | Sort-Object) -join ',')
    $expectedText = (@($Expected | Sort-Object) -join ',')
    if ($actualText -ne $expectedText) { throw "$Label expected [$expectedText], found [$actualText]" }
}

function Assert-ExactParentDs($Child, $Parent, [int[]]$ExpectedTags) {
    $missing = @($ExpectedTags | Where-Object { $Child.Tags -notcontains $_ })
    if ($missing.Count -gt 0) { throw "Parent expects DS for unpublished authenticated child key tag(s): $($missing -join ',')" }
    Assert-Tags $Parent.Tags $ExpectedTags 'parent DS tags'
    $expected = @($Child.DerivedDs | Where-Object { $ExpectedTags -contains $_.Tag } | ForEach-Object { $_.Canonical } | Sort-Object)
    $actual = @($Parent.Records | ForEach-Object { $_.Canonical } | Sort-Object)
    if (($expected -join '|') -ne ($actual -join '|')) {
        throw "Parent DS RDATA does not cryptographically match authenticated child DNSKEYs. Expected [$($expected -join ' | ')], found [$($actual -join ' | ')]"
    }
}

function Assert-ParentNs([string]$ExpectedNs) {
    $parent = Get-ParentSnapshot
    if (($parent.Nameservers -join ',') -ne $ExpectedNs.ToLowerInvariant()) {
        throw "Parent NS changed; expected $ExpectedNs, found $($parent.Nameservers -join ',')"
    }
}

function Wait-VerifiedWindow(
    [string]$Label,
    [int]$RequiredSeconds,
    [int]$ObservationSeconds,
    [scriptblock]$Invariant
) {
    $duration = [Math]::Max($RequiredSeconds, $ObservationSeconds)
    $started = [DateTimeOffset]::UtcNow
    $deadline = $started.AddSeconds($duration + 120)
    do {
        & $Invariant
        $elapsed = [int]([DateTimeOffset]::UtcNow - $started).TotalSeconds
        Write-Host "VERIFY: $Label elapsed=${elapsed}s required=${duration}s"
        if ($elapsed -ge $duration) { return }
        Start-Sleep -Seconds 1
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "$Label did not remain valid for the required $duration seconds"
}

function Get-RolloverMetadata {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $phaseOutput = @(docker compose @script:ComposeArgs run --rm --no-deps ksk-rollover phase 2>$null)
    $phaseExit = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    if ($phaseExit -ne 0) { throw "Could not read saved rollover phase (exit $phaseExit)" }
    $phase = @($phaseOutput | Where-Object { $_ -match '^(not-started|baseline|new-key-published|new-key-active|complete)$' } | Select-Object -Last 1)
    if ($phase.Count -ne 1) { throw 'Could not parse saved rollover phase' }
    if ($phase[0] -eq 'not-started') {
        return [pscustomobject]@{ Phase = 'not-started'; OldTag = 0; NewTag = 0 }
    }
    $ErrorActionPreference = 'Continue'
    $oldOutput = @(docker compose @script:ComposeArgs run --rm --no-deps ksk-rollover old-tag 2>$null)
    $ErrorActionPreference = $oldPreference
    if ($LASTEXITCODE -ne 0) { throw 'Could not read saved predecessor tag' }
    $ErrorActionPreference = 'Continue'
    $newOutput = @(docker compose @script:ComposeArgs run --rm --no-deps ksk-rollover new-tag 2>$null)
    $ErrorActionPreference = $oldPreference
    if ($LASTEXITCODE -ne 0) { throw 'Could not read saved successor tag' }
    $old = @($oldOutput | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1)
    $new = @($newOutput | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1)
    if ($old.Count -ne 1 -or $new.Count -ne 1) { throw 'Saved rollover metadata is malformed' }
    return [pscustomobject]@{ Phase = $phase[0]; OldTag = [int]$old[0]; NewTag = [int]$new[0] }
}

function Assert-StableLiveState {
    $child = Get-ChildSnapshot
    $parent = Get-ParentSnapshot
    if ($child.Tags.Count -ne 1 -or $parent.Tags.Count -ne 1) { throw 'Stable state requires exactly one child key and one parent DS' }
    Assert-ExactParentDs $child $parent @($child.Tags[0])
    Assert-StableBindKey $child.Tags[0]
    Assert-ParentNs 'ns.victim.test.'
    Assert-ValidatedAddress 'stable-state verification'
    return [int]$child.Tags[0]
}
