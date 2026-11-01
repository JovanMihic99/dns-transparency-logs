#!/usr/bin/env bash
# Bash port of test-double-ds-rollover.ps1: run scenario 3; on failure point to the conservative reset.
# Lab only. Usage: sudo bash lab/test-double-ds-rollover.sh [observation-seconds 0-300, default 5]
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if bash "$REPO_ROOT/scenarios/double-ds-rollover/rollover.sh" "${1:-5}"; then
  echo "All legitimate Double-DS rollover checks passed."
else
  echo "ERROR: Scenario 3 failed with exit code $?" >&2
  echo "Run lab/reset-double-ds-rollover.sh for conservative live-state recovery."
  exit 1
fi
