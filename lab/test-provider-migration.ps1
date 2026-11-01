$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$Compose = @(
    'compose',
    '-f', (Join-Path $RepositoryRoot 'lab/docker-compose.yml'),
    '-f', (Join-Path $RepositoryRoot 'scenarios/provider-migration/docker-compose.yml'),
    '--profile', 'tools'
)
$ResetRequired = $false
function Get-CollectorEventLines {
    $output = docker exec lokey-collector cat /app/data/events.jsonl 2>$null
    if ($LASTEXITCODE -ne 0) { return @() }
    return @($output)
}

$StartLineCount = @(Get-CollectorEventLines).Count

function Invoke-Migration([string]$Command) {
    $output = docker @Compose run --rm --no-deps provider-migration $Command | Out-String
    if ($LASTEXITCODE -ne 0) { throw "provider-migration $Command failed.`n$output" }
    $output | Write-Host
    return $output
}

function Assert-ValidatedAddress {
    $answer = docker @Compose exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'Unbound query failed.' }
    if ($answer -notmatch 'status: NOERROR' -or
        $answer -notmatch 'flags:.*\bad\b' -or
        $answer -notmatch 'A\s+192\.0\.2\.10') {
        throw "Expected NOERROR, AD=true, and 192.0.2.10.`n$answer"
    }
}

function Assert-CollectorEvents {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        $lines = @(Get-CollectorEventLines | Select-Object -Skip $StartLineCount)
        $events = @($lines | ForEach-Object {
            try { $_ | ConvertFrom-Json } catch { $null }
        } | Where-Object { $null -ne $_ })

        $dsAdded = @($events | Where-Object {
            $_.observation.changes -contains 'DS_ADDED' -and $_.assessment.risk -eq 'low'
        }).Count -gt 0
        $nsChanged = @($events | Where-Object {
            $_.observation.changes -contains 'NS_CHANGED' -and
            $_.observation.changes -contains 'DNSKEY_CHANGED' -and
            $_.assessment.risk -eq 'low'
        }).Count -gt 0
        $dsRemoved = @($events | Where-Object {
            $_.observation.changes -contains 'DS_REMOVED' -and $_.assessment.risk -eq 'low'
        }).Count -gt 0
        if ($dsAdded -and $nsChanged -and $dsRemoved) { return }
        Start-Sleep -Seconds 1
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Collector did not emit the expected low-risk DS_ADDED, provider switch, and DS_REMOVED events."
}

Push-Location $RepositoryRoot
try {
    $collector = docker ps --filter 'name=^/lokey-collector$' --filter 'status=running' --format '{{.Names}}'
    if ($collector -ne 'lokey-collector') {
        throw 'The collector must be running before the migration test so it can prove pre-announcement observation.'
    }

    docker @Compose build provider-migration | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the provider-migration image.' }
    docker @Compose up -d --no-deps --force-recreate tld | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not apply the exact TLD update-policy permission.' }
    docker @Compose up -d new-provider | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the isolated new-provider service.' }

    $baseline = Invoke-Migration 'status'
    if ($baseline -notmatch 'state=1: OLD NS / OLD DS') {
        throw "The shared lab is not at the legitimate provider baseline. No migration was attempted.`n$baseline"
    }
    Assert-ValidatedAddress

    $ResetRequired = $true
    Invoke-Migration 'run' | Out-Null
    $complete = Invoke-Migration 'status'
    if ($complete -notmatch 'state=4: NEW NS / NEW DS') {
        throw "Migration did not reach the stable new-provider state.`n$complete"
    }
    Assert-ValidatedAddress
    Assert-CollectorEvents
    Write-Host 'PASS: provider migration remained validated and was classified as low risk.'
}
finally {
    if ($ResetRequired) {
        Write-Host 'Returning through the safe reverse migration...'
        Invoke-Migration 'reset' | Out-Null
        $reset = Invoke-Migration 'status'
        if ($reset -notmatch 'state=1: OLD NS / OLD DS') {
            throw "Safe reset did not restore the original provider baseline.`n$reset"
        }
        Assert-ValidatedAddress
    }
    Pop-Location
}
