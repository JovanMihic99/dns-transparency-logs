$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Push-Location $PSScriptRoot

function Assert-ExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE" }
}

function Invoke-Rollover([string]$Command) {
    docker compose run --rm --no-deps ksk-rollover $Command | Out-Host
    Assert-ExitCode "ksk-rollover $Command"
}

function Invoke-CdsSync {
    docker compose run --rm --no-deps cds-sync sync | Out-Host
    Assert-ExitCode 'CDS synchronization'
}

function Get-Phase {
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = docker compose run --rm --no-deps ksk-rollover phase 2>$null
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldPreference
    if ($exitCode -ne 0) { throw "read rollover phase failed with exit code $exitCode" }
    return @($output | Where-Object { $_ -match '^(not-started|baseline|new-key-published|new-key-active|complete)$' } | Select-Object -Last 1)[0]
}

function Assert-Validated {
    docker compose exec -T unbound unbound-control flush_zone victim.test. | Out-Host
    Assert-ExitCode 'flush Unbound cache'
    $answer = docker compose exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String
    Assert-ExitCode 'query Unbound during recovery'
    if ($answer -notmatch 'status: NOERROR' -or $answer -notmatch 'flags:.*\bad\b' -or $answer -notmatch 'A\s+192\.0\.2\.10') {
        throw 'Recovery did not preserve AD=true and 192.0.2.10'
    }
}

try {
    $phase = Get-Phase
    if ($phase -eq 'not-started') {
        Invoke-CdsSync
        Assert-Validated
        Write-Host 'CDS rollover reset: stable provider state already active.'
        return
    }
    if ($phase -eq 'baseline') {
        Invoke-Rollover 'resume-begin'
        $phase = 'new-key-published'
    }
    if ($phase -eq 'new-key-published') {
        Invoke-Rollover 'publish-cds-both'
        Invoke-CdsSync
        Assert-Validated
        Invoke-Rollover 'acknowledge-published'
        $phase = 'new-key-active'
    }
    if ($phase -eq 'new-key-active') {
        Invoke-Rollover 'publish-cds-new'
        Invoke-CdsSync
        Assert-Validated
        Invoke-Rollover 'acknowledge-withdrawn'
        $phase = 'complete'
    }
    if ($phase -eq 'complete') {
        Invoke-Rollover 'reconcile'
        Invoke-CdsSync
        Assert-Validated
        Write-Host 'CDS rollover reset: transition safely completed at a stable key.'
    }
}
finally {
    Pop-Location
}
