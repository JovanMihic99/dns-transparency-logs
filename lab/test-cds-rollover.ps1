param(
    [ValidateRange(0, 60)]
    [int]$ObservationDelaySeconds = 2,
    [switch]$SkipExistingScenarioRegressions
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scenario = Join-Path $repoRoot 'scenarios\cds-rollover\rollover.ps1'

try {
    & $scenario -ObservationDelaySeconds $ObservationDelaySeconds
    if ($LASTEXITCODE -ne 0) { throw "CDS rollover scenario failed with exit code $LASTEXITCODE" }

    if (-not $SkipExistingScenarioRegressions) {
        & (Join-Path $PSScriptRoot 'test-ksk-rollover.ps1')
        if ($LASTEXITCODE -ne 0) { throw "Scenario 2 regression failed with exit code $LASTEXITCODE" }
        & (Join-Path $PSScriptRoot 'test-registrar-hijack.ps1')
        if ($LASTEXITCODE -ne 0) { throw "Registrar hijack regression failed with exit code $LASTEXITCODE" }
    }
    Write-Host 'All CDS rollover checks and requested existing-scenario regressions passed.'
}
catch {
    Write-Error $_
    Write-Host 'Run .\reset-cds-rollover.ps1 from lab\ to safely complete a partial transition.'
    exit 1
}
