$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Push-Location $PSScriptRoot
$restoreNeeded = $false
$testPassed = $false

function ConvertTo-NormalizedDs([string]$Raw) {
    $parts = $Raw.Trim() -split '\s+'
    if ($parts.Count -lt 4) { throw "Could not parse DS record: $Raw" }
    return "$($parts[0]) $($parts[1]) $($parts[2]) $($parts[3..($parts.Count - 1)] -join '')"
}

function Invoke-NsUpdate([string]$Rdata) {
    $update = @"
server 172.30.0.11 53
zone test.
update delete victim.test. DS
update add victim.test. 30 IN DS $Rdata
send
"@
    $update | docker compose exec -T tld nsupdate -k /opt/lab/registrar.key
    if ($LASTEXITCODE -ne 0) { throw "nsupdate failed with exit code $LASTEXITCODE" }
}

function Wait-ForDs([string]$Expected) {
    foreach ($attempt in 1..30) {
        $rawObserved = (docker compose exec -T root dig '@172.30.0.11' victim.test. DS +short | Out-String).Trim()
        $observed = ConvertTo-NormalizedDs $rawObserved
        if ($observed -eq $Expected) { return }
        Start-Sleep -Seconds 1
    }
    throw "Timed out waiting for the test TLD to publish the requested DS"
}

try {
    $rawDs = (docker compose exec -T root dig '@172.30.0.11' victim.test. DS +short | Out-String).Trim()
    if (-not $rawDs) { throw 'The working victim.test DS record was not found' }
    if ($rawDs -match "`r|`n") { throw 'Expected exactly one victim.test DS record' }
    $correctDs = ConvertTo-NormalizedDs $rawDs

    $last = $correctDs.Substring($correctDs.Length - 1, 1)
    $replacement = if ($last -eq '0') { '1' } else { '0' }
    $badDs = $correctDs.Substring(0, $correctDs.Length - 1) + $replacement

    Write-Host 'Installing a deliberately incorrect victim.test DS record...'
    Invoke-NsUpdate $badDs
    $restoreNeeded = $true
    Wait-ForDs $badDs
    docker compose restart unbound | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not restart Unbound to clear its cache' }

    $rendered = (docker compose exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments | Out-String)
    if ($rendered -notmatch 'status: SERVFAIL') {
        throw "Expected SERVFAIL with the incorrect DS, but received:`n$rendered"
    }
    if ($rendered -match 'flags:.*\bad\b') {
        throw 'The invalid response unexpectedly contained the AD flag'
    }
    Write-Host 'PASS: the incorrect DS caused DNSSEC validation failure (SERVFAIL, no AD flag).'
    $testPassed = $true
}
finally {
    if ($restoreNeeded) {
        Write-Host 'Restoring the correct victim.test DS record...'
        Invoke-NsUpdate $correctDs
        Wait-ForDs $correctDs
        docker compose restart unbound | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'The DS was restored, but Unbound could not be restarted' }
        docker compose exec -T root sh /opt/lab/test-dnssec.sh | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'The correct DS was restored, but the positive DNSSEC checks failed' }
    }
    Pop-Location
}

if (-not $testPassed) { exit 1 }

