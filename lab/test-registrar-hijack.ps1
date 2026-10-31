$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Push-Location $PSScriptRoot
$restoreRequired = $false
$scenarioPassed = $false

function Assert-ExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE" }
}

function Invoke-Registrar([string]$Command) {
    docker compose run --rm --no-deps registrar $Command | Out-Host
    Assert-ExitCode "registrar $Command"
}

function ConvertTo-NormalizedDs([string]$Raw) {
    $parts = $Raw.Trim() -split '\s+'
    if ($parts.Count -lt 4) { throw "Could not parse DS record: $Raw" }
    return "$($parts[0]) $($parts[1]) $($parts[2]) $($parts[3..($parts.Count - 1)] -join '')"
}

function Get-ChildDs([string]$Server) {
    $line = (docker compose exec -T root sh -c "dig '@$Server' victim.test. DNSKEY +noall +answer | dnssec-dsfromkey -2 -f - victim.test." | Out-String).Trim()
    Assert-ExitCode 'derive child DS'
    $parts = $line -split '\s+'
    if ($parts.Count -lt 7) { throw "Could not parse derived DS: $line" }
    return ConvertTo-NormalizedDs "$($parts[3]) $($parts[4]) $($parts[5]) $($parts[6..($parts.Count - 1)] -join '')"
}

function Get-ParentDs {
    $line = (docker compose exec -T root dig '@172.30.0.11' victim.test. DS +short | Out-String).Trim()
    Assert-ExitCode 'read parent DS'
    return ConvertTo-NormalizedDs $line
}

function Get-ParentNs {
    $line = (docker compose exec -T root dig '@172.30.0.11' victim.test. NS +noall +answer +authority | Out-String).Trim()
    Assert-ExitCode 'read parent NS'
    $parts = $line -split '\s+'
    if ($parts.Count -lt 5) { throw "Could not parse parent NS record: $line" }
    return $parts[-1]
}

function Assert-DirectAnswer([string]$Server, [string]$Expected) {
    $answer = (docker compose exec -T root dig "@$Server" www.victim.test. A +short | Out-String).Trim()
    Assert-ExitCode "direct query to $Server"
    if ($answer -ne $Expected) { throw "Expected $Expected from $Server, got '$answer'" }
    Write-Host "PASS: authoritative server $Server returns $Expected."
}

function Assert-SignedAttacker {
    $answer = docker compose exec -T root dig '@172.30.0.13' victim.test. DNSKEY +dnssec +noall +answer | Out-String
    Assert-ExitCode 'attacker DNSKEY query'
    if ($answer -notmatch '\sDNSKEY\s') { throw 'Attacker does not publish DNSKEY' }
    if ($answer -notmatch '\sRRSIG\s+DNSKEY\s') { throw 'Attacker DNSKEY RRset is not signed' }
    Write-Host 'PASS: attacker publishes DNSKEY and an RRSIG over DNSKEY.'
}

function Restart-Unbound {
    docker compose restart unbound | Out-Host
    Assert-ExitCode 'restart Unbound'
}

function Assert-ValidatedAnswer([string]$Expected) {
    foreach ($attempt in 1..30) {
        $rendered = (docker compose exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String)
        if ($rendered -match 'status: NOERROR' -and
            $rendered -match 'flags:.*\bad\b' -and
            $rendered -match "A\s+$([regex]::Escape($Expected))") {
            Write-Host "PASS: Unbound validates $Expected and returns AD."
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "Unbound did not return validated address $Expected with AD"
}

try {
    docker compose build registrar | Out-Host
    Assert-ExitCode 'build registrar image'
    docker compose up -d | Out-Host
    Assert-ExitCode 'start DNS lab'

    Assert-DirectAnswer '172.30.0.12' '192.0.2.10'
    Assert-DirectAnswer '172.30.0.13' '192.0.2.66'
    Assert-SignedAttacker

    $attackerKeyBefore = Get-ChildDs '172.30.0.13'
    $attackerKeyAfter = ''
    docker compose restart attacker | Out-Host
    Assert-ExitCode 'restart attacker'
    foreach ($attempt in 1..30) {
        try {
            $attackerKeyAfter = Get-ChildDs '172.30.0.13'
            if ($attackerKeyAfter -eq $attackerKeyBefore) { break }
        } catch { }
        Start-Sleep -Seconds 1
    }
    if ($attackerKeyAfter -ne $attackerKeyBefore) { throw 'Attacker DNSSEC identity changed after restart' }
    Write-Host 'PASS: attacker DNSSEC identity survives restart.'

    Invoke-Registrar 'restore'
    Restart-Unbound
    Assert-ValidatedAnswer '192.0.2.10'
    Invoke-Registrar 'status'

    Invoke-Registrar 'unauthorized-test'

    $restoreRequired = $true
    Invoke-Registrar 'hijack'
    $parentNs = Get-ParentNs
    if ($parentNs -ne 'ns.attacker.test.') { throw "Hijacked NS is '$parentNs', expected ns.attacker.test." }
    if ((Get-ParentDs) -ne (Get-ChildDs '172.30.0.13')) { throw 'Published attacker DS does not match attacker DNSKEY' }
    Write-Host 'PASS: parent NS and DS match the signed attacker zone.'
    Restart-Unbound
    Assert-ValidatedAnswer '192.0.2.66'
    Invoke-Registrar 'status'

    $scenarioPassed = $true
}
finally {
    if ($restoreRequired) {
        Write-Host 'Restoring the legitimate provider delegation...'
        Invoke-Registrar 'restore'
    }
    Restart-Unbound
    Assert-ValidatedAnswer '192.0.2.10'
    docker compose exec -T root sh /opt/lab/test-dnssec.sh | Out-Host
    Assert-ExitCode 'DNSSEC baseline regression'
    Pop-Location
}

if (-not $scenarioPassed) { exit 1 }
Write-Host 'All registrar baseline -> hijack -> restore regression checks passed.'

