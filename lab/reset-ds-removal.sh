#!/usr/bin/env bash
# Bash port of reset-ds-removal.ps1: restore the provider DS (derived from its authenticated DNSKEY).
# Lab only. Usage: sudo bash lab/reset-ds-removal.sh
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$LAB/.." && pwd)"
cd "$ROOT"
dc() { docker compose -p lab -f "$LAB/docker-compose.yml" -f "$ROOT/scenarios/ds-removal/docker-compose.yml" --profile tools "$@"; }
dc run --rm --no-deps ds-removal restore
dc exec -T unbound unbound-control flush_zone victim.test.
dc exec -T root sh /opt/lab/test-dnssec.sh
