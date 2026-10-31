$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$baseCompose = Join-Path $PSScriptRoot 'docker-compose.yml'
$baseArgs = @('-p', 'lab', '-f', $baseCompose)
Push-Location $repoRoot

function Assert-ExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE" }
}

try {
    $beforeDs = (docker compose @baseArgs exec -T root dig '@172.30.0.11' victim.test. DS +short | Out-String).Trim()
    Assert-ExitCode 'read parent DS before reset'
    $beforeNsRaw = (docker compose @baseArgs exec -T root dig '@172.30.0.11' victim.test. NS +noall +answer +authority | Out-String).Trim()
    Assert-ExitCode 'read parent NS before reset'

    # Recreate only provider from the base definition. This reattaches the
    # untouched provider_state volume; all other lab services keep running.
    docker compose @baseArgs up -d --no-deps --force-recreate provider | Out-Host
    Assert-ExitCode 'restore base provider service'

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $dnskeys = docker compose @baseArgs exec -T root dig '@172.30.0.12' victim.test. DNSKEY +short 2>$null
        $queryExit = $LASTEXITCODE
        $ErrorActionPreference = $oldPreference
        if ($queryExit -eq 0 -and @($dnskeys | Where-Object { $_ -match '^257\s+3\s+13\s+' }).Count -eq 1) {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Base provider did not become ready after reset' }

    $afterDs = (docker compose @baseArgs exec -T root dig '@172.30.0.11' victim.test. DS +short | Out-String).Trim()
    Assert-ExitCode 'read parent DS after reset'
    $afterNsRaw = (docker compose @baseArgs exec -T root dig '@172.30.0.11' victim.test. NS +noall +answer +authority | Out-String).Trim()
    Assert-ExitCode 'read parent NS after reset'
    if ($afterDs -ne $beforeDs) { throw 'Parent DS changed while resetting the ZSK scenario' }
    if ($afterNsRaw -ne $beforeNsRaw) { throw 'Parent NS changed while resetting the ZSK scenario' }

    # Cached experimental DNSKEY contains the same flag-257 key used by the
    # restored CSK, so base signatures remain verifiable. Flush the lab
    # resolver as an additional deterministic test boundary.
    docker compose @baseArgs exec -T unbound unbound-control flush_zone victim.test. | Out-Host
    Assert-ExitCode 'flush Unbound after provider reset'
    $answer = docker compose @baseArgs exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String
    Assert-ExitCode 'validate restored provider through Unbound'
    if ($answer -notmatch 'status: NOERROR' -or $answer -notmatch 'flags:.*\bad\b' -or $answer -notmatch 'A\s+192\.0\.2\.10') {
        throw 'Restored base provider did not return 192.0.2.10 with AD=true'
    }
    Write-Host 'ZSK reset passed: original provider_state restored; parent DS/NS unchanged; AD=true.'
}
finally {
    Pop-Location
}
