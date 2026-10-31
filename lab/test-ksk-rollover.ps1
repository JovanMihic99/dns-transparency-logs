$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Push-Location $PSScriptRoot
$rolloverStarted = $false

function Assert-ExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE" }
}

function Invoke-Rollover([string]$Command) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = docker compose run --rm --no-deps ksk-rollover $Command
    $commandExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    $output | Out-Host
    if ($commandExitCode -ne 0) { throw "ksk-rollover $Command failed with exit code $commandExitCode" }
    return $output
}

function Read-NumericOutput($Output, [string]$Label) {
    $value = @($Output | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1)
    if ($value.Count -ne 1) { throw "Could not read $Label from scenario output" }
    return [int]$value[0]
}

function Flush-Unbound {
    docker compose exec -T unbound unbound-control flush_zone victim.test. | Out-Host
    Assert-ExitCode 'flush Unbound victim.test cache'
}

function Assert-Validated([string]$Phase) {
    Flush-Unbound
    $answer = docker compose exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String
    Assert-ExitCode "query Unbound during $Phase"
    if ($answer -notmatch 'status: NOERROR' -or
        $answer -notmatch 'flags:.*\bad\b' -or
        $answer -notmatch 'A\s+192\.0\.2\.10') {
        throw "Unbound did not return 192.0.2.10 with AD=true during $Phase"
    }
    Write-Host "PASS: Unbound returned AD=true during $Phase."
}

try {
    docker compose build registrar | Out-Host
    Assert-ExitCode 'build registrar'
    docker compose up -d | Out-Host
    Assert-ExitCode 'start lab'

    # The bind-mounted Unbound configuration may have changed without a
    # container recreation. HUP reloads it once before the transition.
    docker compose kill -s HUP unbound | Out-Host
    Assert-ExitCode 'reload Unbound configuration'
    Start-Sleep -Seconds 2

    & "$PSScriptRoot\reset-ksk-rollover.ps1"
    Assert-ExitCode 'establish stable rollover baseline'
    Assert-Validated 'baseline'

    $beginOutput = Invoke-Rollover 'begin'
    $rolloverStarted = $true
    $oldLine = @($beginOutput | Where-Object { $_ -match '^OLD_TAG=\d+$' } | Select-Object -Last 1)[0]
    $newLine = @($beginOutput | Where-Object { $_ -match '^NEW_TAG=\d+$' } | Select-Object -Last 1)[0]
    $oldTag = [int]($oldLine -replace '^OLD_TAG=', '')
    $newTag = [int]($newLine -replace '^NEW_TAG=', '')
    if ($oldTag -eq $newTag) { throw 'BIND did not generate an independent successor key' }
    Assert-Validated 'new-key prepublication with old parent DS'

    docker compose run --rm --no-deps registrar sync-provider-ds | Out-Host
    Assert-ExitCode 'publish double provider DS set'
    Assert-Validated 'double DNSKEY and double DS state'

    Invoke-Rollover 'acknowledge-published' | Out-Null
    Assert-Validated 'new-key activation'

    docker compose run --rm --no-deps registrar sync-provider-ds --key-tag $newTag | Out-Host
    Assert-ExitCode 'withdraw old provider DS'
    Assert-Validated 'new-only parent DS before old-key retirement'

    Invoke-Rollover 'acknowledge-withdrawn' | Out-Null
    Assert-Validated 'completed rollover'

    docker compose exec -T root sh /opt/lab/test-dnssec.sh | Out-Host
    Assert-ExitCode 'DNSSEC baseline regression'
    Write-Host "All legitimate Double-KSK rollover checks passed: $oldTag -> $newTag."
}
finally {
    if ($rolloverStarted) {
        & "$PSScriptRoot\reset-ksk-rollover.ps1"
    }
    Pop-Location
}
