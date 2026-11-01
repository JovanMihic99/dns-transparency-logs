#!/usr/bin/env bash
# Bash port of reset-unsigned-ns-change.ps1: undo an interrupted scenario 8 (NS back, signed provider, DS restored).
# Like the .ps1, it runs every step even if one fails; the final DNSSEC checks show the result.
# Lab only. Usage: sudo bash lab/reset-unsigned-ns-change.sh
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$LAB/.." && pwd)"
cd "$ROOT"
dc_base() { docker compose -p lab -f "$LAB/docker-compose.yml" "$@"; }
dc_all()  { docker compose -p lab -f "$LAB/docker-compose.yml" -f "$ROOT/scenarios/unsigned-ns-change/docker-compose.yml" --profile tools "$@"; }
dc_all run --rm --no-deps unsigned-change reverse
dc_base exec -T unbound unbound-control flush_zone victim.test.
sleep 22
dc_base up -d --no-deps --force-recreate provider
sleep 12
dc_all run --rm --no-deps unsigned-change restore-ds
dc_base exec -T unbound unbound-control flush_zone victim.test.
dc_base exec -T root sh /opt/lab/test-dnssec.sh
