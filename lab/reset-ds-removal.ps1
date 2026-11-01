$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$args=@('-p','lab','-f',(Join-Path $PSScriptRoot 'docker-compose.yml'),'-f',(Join-Path $root 'scenarios/ds-removal/docker-compose.yml'),'--profile','tools')
docker compose @args run --rm --no-deps ds-removal restore
if($LASTEXITCODE){exit $LASTEXITCODE}
docker compose @args exec -T unbound unbound-control flush_zone victim.test.
docker compose @args exec -T root sh /opt/lab/test-dnssec.sh
