param(
    [ValidateRange(0, 300)]
    [int]$ObservationDurationSeconds = 5
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scenario = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'scenarios\double-ds-rollover\rollover.ps1'
try {
    & $scenario -ObservationDurationSeconds $ObservationDurationSeconds
    if ($LASTEXITCODE -ne 0) { throw "Scenario 3 failed with exit code $LASTEXITCODE" }
    Write-Host 'All legitimate Double-DS rollover checks passed.'
}
catch {
    Write-Error $_
    Write-Host 'Run .\reset-double-ds-rollover.ps1 from lab\ for conservative live-state recovery.'
    exit 1
}
