#!/usr/bin/env bash
# Bash port of reset-cds-rollover.ps1: walk an interrupted CDS-driven rollover forward to a stable key.
# Lab only. Usage: sudo bash lab/reset-cds-rollover.sh
set -euo pipefail
cd "$(dirname "$0")"

ZONE="victim.test."
PROVIDER_ADDR="192.0.2.10"

die() { echo "ERROR: $*" >&2; exit 1; }

invoke_rollover() {
  docker compose run --rm --no-deps ksk-rollover "$1" || die "ksk-rollover $1 failed with exit code $?"
}

invoke_cds_sync() {
  docker compose run --rm --no-deps cds-sync sync || die "CDS synchronization failed with exit code $?"
}

get_phase() {
  local out phase
  out=$(docker compose run --rm --no-deps -T ksk-rollover phase 2>/dev/null) \
    || die "read rollover phase failed with exit code $?"
  phase=$(printf '%s\n' "$out" | tr -d '\r' \
    | grep -E '^(not-started|baseline|new-key-published|new-key-active|complete)$' | tail -n 1 || true)
  [ -n "$phase" ] || die "could not read the rollover phase"
  echo "$phase"
}

assert_validated() {
  local answer
  docker compose exec -T unbound unbound-control flush_zone "$ZONE" || die "flush Unbound cache failed with exit code $?"
  answer=$(docker compose exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer) \
    || die "query Unbound during recovery failed with exit code $?"
  if ! grep -q 'status: NOERROR' <<<"$answer" \
     || ! grep -Eq 'flags:.*\bad\b' <<<"$answer" \
     || ! grep -Eq "A[[:space:]]+${PROVIDER_ADDR//./\\.}" <<<"$answer"; then
    die "Recovery did not preserve AD=true and ${PROVIDER_ADDR}"
  fi
}

phase=$(get_phase)
echo "Current rollover phase: $phase"

if [ "$phase" = "not-started" ]; then
  invoke_cds_sync
  assert_validated
  echo "CDS rollover reset: stable provider state already active."
  exit 0
fi
if [ "$phase" = "baseline" ]; then
  invoke_rollover resume-begin
  phase="new-key-published"
fi
if [ "$phase" = "new-key-published" ]; then
  invoke_rollover publish-cds-both
  invoke_cds_sync
  assert_validated
  invoke_rollover acknowledge-published
  phase="new-key-active"
fi
if [ "$phase" = "new-key-active" ]; then
  invoke_rollover publish-cds-new
  invoke_cds_sync
  assert_validated
  invoke_rollover acknowledge-withdrawn
  phase="complete"
fi
if [ "$phase" = "complete" ]; then
  invoke_rollover reconcile
  invoke_cds_sync
  assert_validated
  echo "CDS rollover reset: transition safely completed at a stable key."
fi
