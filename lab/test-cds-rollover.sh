#!/usr/bin/env bash
# Bash port of test-cds-rollover.ps1: run scenario 4, then (unless skipped) the existing regressions.
# Lab only. Usage: sudo bash lab/test-cds-rollover.sh [observation-delay 0-60, default 2] [--skip-existing-regressions]
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$LAB/.." && pwd)"

DELAY=2
SKIP=0
for arg in "$@"; do
  case "$arg" in
    --skip-existing-regressions) SKIP=1 ;;
    *) DELAY="$arg" ;;
  esac
done

fail() {
  echo "ERROR: $*" >&2
  echo "Run lab/reset-cds-rollover.sh to safely complete a partial transition."
  exit 1
}

bash "$REPO_ROOT/scenarios/cds-rollover/rollover.sh" "$DELAY" || fail "CDS rollover scenario failed with exit code $?"

if [ "$SKIP" -eq 0 ]; then
  bash "$LAB/test-ksk-rollover.sh" "$DELAY" || fail "Scenario 2 regression failed with exit code $?"
  [ -f "$LAB/test-registrar-hijack.sh" ] \
    || fail "test-registrar-hijack.sh is not ported yet; rerun with --skip-existing-regressions"
  bash "$LAB/test-registrar-hijack.sh" || fail "Registrar hijack regression failed with exit code $?"
fi
echo "All CDS rollover checks and requested existing-scenario regressions passed."
