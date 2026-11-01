$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$Compose = @(
    'compose',
    '-f', (Join-Path $RepositoryRoot 'lab/docker-compose.yml'),
    '-f', (Join-Path $RepositoryRoot 'scenarios/provider-migration/docker-compose.yml'),
    '--profile', 'tools'
)

Push-Location $RepositoryRoot
try {
    docker @Compose up -d new-provider | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the isolated new-provider service.' }

    docker @Compose run --rm --no-deps provider-migration reset | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'State-driven provider migration reset failed.' }

    docker @Compose run --rm --no-deps provider-migration status | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Post-reset status verification failed.' }
}
finally {
    Pop-Location
}
