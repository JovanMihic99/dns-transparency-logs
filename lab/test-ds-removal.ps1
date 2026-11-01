$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$compose = @('-p','lab','-f',(Join-Path $PSScriptRoot 'docker-compose.yml'),'-f',(Join-Path $root 'scenarios/ds-removal/docker-compose.yml'),'--profile','tools')
$start = @(docker exec lokey-collector cat /app/data/events.jsonl 2>$null).Count
function Run([string]$Command) { docker compose @compose run --rm --no-deps ds-removal $Command | Out-Host; if($LASTEXITCODE){throw "ds-removal $Command failed"} }
function Flush { docker compose @compose exec -T unbound unbound-control flush_zone victim.test. | Out-Host; if($LASTEXITCODE){throw 'cache flush failed'} }
function Answer([bool]$Ad) {
    $out = docker compose @compose exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer | Out-String
    if($out -notmatch 'status: NOERROR' -or $out -notmatch 'A\s+192\.0\.2\.10'){throw "wrong resolver answer`n$out"}
    $hasAd = $out -match 'flags:.*\bad\b'; if($hasAd -ne $Ad){throw "AD expected=$Ad`n$out"}
}
Push-Location $root
try {
    docker compose @compose build ds-removal | Out-Host; if($LASTEXITCODE){throw 'build failed'}
    Run restore; Flush; Answer $true
    Run remove; Flush; Answer $false
    $deadline=[DateTimeOffset]::UtcNow.AddSeconds(45); $seen=$false
    do {
        $lines=@(docker exec lokey-collector cat /app/data/events.jsonl 2>$null | Select-Object -Skip $start)
        foreach($line in $lines){ try{$e=$line|ConvertFrom-Json}catch{continue}; if($e.observation.changes -contains 'DS_ALL_REMOVED' -and $e.assessment.risk -eq 'high'){$seen=$true} }
        if(-not $seen){Start-Sleep 1}
    } while(-not $seen -and [DateTimeOffset]::UtcNow -lt $deadline)
    if(-not $seen){throw 'collector did not emit HIGH DS_ALL_REMOVED'}
    Write-Host 'PASS: DS removal returned insecure NOERROR/AD=false and collector HIGH.'
}
finally { Run restore; Flush; Answer $true; docker compose @compose exec -T root sh /opt/lab/test-dnssec.sh | Out-Host }
Pop-Location
