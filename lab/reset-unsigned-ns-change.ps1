$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$base=@('-p','lab','-f',(Join-Path $PSScriptRoot 'docker-compose.yml'))
$all=@('-p','lab','-f',(Join-Path $PSScriptRoot 'docker-compose.yml'),'-f',(Join-Path $root 'scenarios/unsigned-ns-change/docker-compose.yml'),'--profile','tools')
docker compose @all run --rm --no-deps unsigned-change reverse
docker compose @base exec -T unbound unbound-control flush_zone victim.test.
Start-Sleep 22
docker compose @base up -d --no-deps --force-recreate provider
Start-Sleep 12
docker compose @all run --rm --no-deps unsigned-change restore-ds
docker compose @base exec -T unbound unbound-control flush_zone victim.test.
docker compose @base exec -T root sh /opt/lab/test-dnssec.sh
