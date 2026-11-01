$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$base=@('-p','lab','-f',(Join-Path $PSScriptRoot 'docker-compose.yml'))
$all=@('-p','lab','-f',(Join-Path $PSScriptRoot 'docker-compose.yml'),'-f',(Join-Path $root 'scenarios/unsigned-ns-change/docker-compose.yml'),'--profile','tools')
function Tool([string]$c){docker compose @all run --rm --no-deps unsigned-change $c|Out-Host;if($LASTEXITCODE){throw "unsigned-change $c failed"}}
function Flush {docker compose @base exec -T unbound unbound-control flush_zone victim.test.|Out-Host;if($LASTEXITCODE){throw 'flush failed'}}
function Answer([string]$address,[bool]$ad){$o=docker compose @base exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec +noall +comments +answer|Out-String;if($o-notmatch'status: NOERROR'-or$o-notmatch"A\s+$([regex]::Escape($address))"){throw "bad answer`n$o"};if(($o-match'flags:.*\bad\b')-ne$ad){throw "wrong AD expectation`n$o"}}
function Wait-UnsignedOld {
  $end=[DateTimeOffset]::UtcNow.AddSeconds(45);$seen=@()
  do{try{$s=(docker exec lokey-collector cat /app/data/state.json|ConvertFrom-Json).snapshots.'victim.test';if(@($s.ns)-join',' -eq 'ns.victim.test.' -and @($s.ds).Count-eq 0 -and @($s.dnskey).Count-eq 0){$seen+=@($s.observed_at)}}catch{};if(@($seen|Sort-Object -Unique).Count-lt2){Start-Sleep 1}}while(@($seen|Sort-Object -Unique).Count-lt2-and[DateTimeOffset]::UtcNow-lt$end)
  if(@($seen|Sort-Object -Unique).Count-lt2){throw 'collector did not establish two unsigned old-provider snapshots'}
}
function Wait-SignedOldNoDs {
  $end=[DateTimeOffset]::UtcNow.AddSeconds(45)
  do{try{$s=(docker exec lokey-collector cat /app/data/state.json|ConvertFrom-Json).snapshots.'victim.test';if(@($s.ns)-join',' -eq 'ns.victim.test.' -and @($s.ds).Count-eq 0 -and @($s.dnskey).Count-gt 0){return}}catch{};Start-Sleep 1}while([DateTimeOffset]::UtcNow-lt$end)
  throw 'collector did not observe the restored signed provider before DS restoration'
}
Push-Location $root
$prepared=$false
try{
 docker compose @all build unsigned-change|Out-Host;if($LASTEXITCODE){throw 'build failed'}
 docker compose @all up -d --no-deps --force-recreate tld|Out-Host
 Tool remove-ds;$prepared=$true;Flush;Answer '192.0.2.10' $false
 docker compose @all up -d --no-deps --force-recreate provider unsigned-new|Out-Host;if($LASTEXITCODE){throw 'unsigned authorities failed'}
 Flush;Answer '192.0.2.10' $false;Wait-UnsignedOld
 $start=@(docker exec lokey-collector cat /app/data/events.jsonl 2>$null).Count
 Tool switch;Flush;Answer '192.0.2.66' $false
 $end=[DateTimeOffset]::UtcNow.AddSeconds(45);$pass=$false
 do{foreach($line in @(docker exec lokey-collector cat /app/data/events.jsonl 2>$null|Select-Object -Skip $start)){try{$e=$line|ConvertFrom-Json}catch{continue};if((@($e.observation.changes)-join',')-eq'NS_CHANGED'-and$e.assessment.risk-eq'medium'){$pass=$true}};if(-not$pass){Start-Sleep 1}}while(-not$pass-and[DateTimeOffset]::UtcNow-lt$end)
 if(-not$pass){throw 'collector did not emit exactly NS_CHANGED at MEDIUM'}
 Write-Host 'PASS: unsigned NS-only change returned 192.0.2.66, AD=false, collector MEDIUM.'
}finally{
 if($prepared){try{Tool reverse;Flush;Wait-UnsignedOld}catch{Write-Warning $_};docker compose @base up -d --no-deps --force-recreate provider|Out-Host;for($i=0;$i-lt30;$i++){docker compose @base exec -T root dig '@172.30.0.12' victim.test. DNSKEY +short 2>$null|Out-Null;if($LASTEXITCODE-eq0){break};Start-Sleep 1};Wait-SignedOldNoDs;Tool restore-ds;Flush;Answer '192.0.2.10' $true;docker compose @base exec -T root sh /opt/lab/test-dnssec.sh|Out-Host}
 Pop-Location
}
