#!/usr/bin/env bash
# Bash port of reset-provider-migration.ps1: state-driven safe return to the original provider.
# Lab only. Usage: sudo bash lab/reset-provider-migration.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
die() { echo "ERROR: $*" >&2; exit 1; }
dc() { docker compose -p lab -f "$ROOT/lab/docker-compose.yml" -f "$ROOT/scenarios/provider-migration/docker-compose.yml" --profile tools "$@"; }
dc up -d new-provider || die "could not start the isolated new-provider service"
dc run --rm --no-deps provider-migration reset || die "state-driven provider migration reset failed"
dc run --rm --no-deps provider-migration status || die "post-reset status verification failed"
