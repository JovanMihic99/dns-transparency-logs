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

function Get-RolloverValue([string]$Command) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = docker compose run --rm --no-deps ksk-rollover $Command 2>$null
    $commandExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    if ($commandExitCode -ne 0) { throw "ksk-rollover $Command failed with exit code $commandExitCode" }
    $value = @($output | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1)
    if ($value.Count -ne 1) { throw "Could not read numeric rollover value for $Command" }
    return [int]$value[0]
}

function Flush-Unbound {
    docker compose exec -T unbound unbound-control flush_zone victim.test. | Out-Host
    Assert-ExitCode 'flush Unbound victim.test cache'
}

function Assert-Validated {
    $answer = docker compose exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String
    Assert-ExitCode 'query Unbound'
    if ($answer -notmatch 'status: NOERROR' -or
        $answer -notmatch 'flags:.*\bad\b' -or
        $answer -notmatch 'A\s+192\.0\.2\.10') {
        throw 'Unbound did not return the provider address with AD=true during rollover recovery'
    }
}

try {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $phaseOutput = docker compose run --rm --no-deps ksk-rollover phase 2>$null
    $phaseExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    if ($phaseExitCode -ne 0) { throw "read rollover phase failed with exit code $phaseExitCode" }
    $phase = @($phaseOutput | Where-Object { $_ -match '^(not-started|baseline|new-key-published|new-key-active|complete)$' } | Select-Object -Last 1)[0]

    if ($phase -eq 'not-started') {
        docker compose run --rm --no-deps registrar sync-provider-ds | Out-Host
        Assert-ExitCode 'synchronize stable provider DS'
        Flush-Unbound
        Assert-Validated
        Write-Host 'Rollover reset: stable provider state already active.'
        return
    }

    if ($phase -eq 'baseline' -or $phase -eq 'complete') {
        try {
            Invoke-Rollover 'reconcile'
            Flush-Unbound
            Assert-Validated
            Write-Host 'Rollover reset: stable state reconciled.'
            return
        } catch {
            Write-Host 'The saved phase is not yet stable; completing it safely...'
        }
    } else {
        Write-Host 'Completing the interrupted rollover safely...'
    }

    $newTag = Get-RolloverValue 'new-tag'
    if ($newTag -eq 0) {
        Invoke-Rollover 'reconcile'
        Flush-Unbound
        Assert-Validated
        return
    }

    docker compose run --rm --no-deps registrar sync-provider-ds | Out-Host
    Assert-ExitCode 'publish both provider DS records'
    Flush-Unbound
    Assert-Validated
    Invoke-Rollover 'acknowledge-published'

    docker compose run --rm --no-deps registrar sync-provider-ds --key-tag $newTag | Out-Host
    Assert-ExitCode 'publish only the new provider DS'
    Flush-Unbound
    Assert-Validated
    Invoke-Rollover 'acknowledge-withdrawn'
    Flush-Unbound
    Assert-Validated
    Write-Host 'Rollover reset: transition completed at the new stable key.'
}
finally {
    Pop-Location
}
