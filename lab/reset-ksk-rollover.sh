#!/usr/bin/env bash
# Bash port of reset-ksk-rollover.ps1: bring the double-KSK rollover back to a stable state.
# Lab only (.test, isolated Docker network). Usage: sudo bash lab/reset-ksk-rollover.sh
set -euo pipefail
cd "$(dirname "$0")"

ZONE="victim.test."
PROVIDER_ADDR="192.0.2.10"

die() { echo "ERROR: $*" >&2; exit 1; }

invoke_rollover() {  # ksk-rollover <command>, output shown
  docker compose run --rm --no-deps ksk-rollover "$1" || die "ksk-rollover $1 failed with exit code $?"
}

get_rollover_value() {  # last purely numeric output line of ksk-rollover <command>
  local out value
  out=$(docker compose run --rm --no-deps -T ksk-rollover "$1" 2>/dev/null) \
    || die "ksk-rollover $1 failed with exit code $?"
  value=$(printf '%s\n' "$out" | tr -d '\r' | grep -E '^[0-9]+$' | tail -n 1 || true)
  [ -n "$value" ] || die "could not read numeric rollover value for $1"
  echo "$value"
}

flush_unbound() {
  docker compose exec -T unbound unbound-control flush_zone "$ZONE" \
    || die "flush Unbound $ZONE cache failed with exit code $?"
}

assert_validated() {  # NOERROR, AD flag, provider address
  local answer
  answer=$(docker compose exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer) \
    || die "query Unbound failed with exit code $?"
  if ! grep -q 'status: NOERROR' <<<"$answer" \
     || ! grep -Eq 'flags:.*\bad\b' <<<"$answer" \
     || ! grep -Eq "A[[:space:]]+${PROVIDER_ADDR//./\\.}" <<<"$answer"; then
    die "Unbound did not return the provider address with AD=true during rollover recovery"
  fi
}

phase_out=$(docker compose run --rm --no-deps -T ksk-rollover phase 2>/dev/null) \
  || die "read rollover phase failed with exit code $?"
phase=$(printf '%s\n' "$phase_out" | tr -d '\r' \
  | grep -E '^(not-started|baseline|new-key-published|new-key-active|complete)$' | tail -n 1 || true)
[ -n "$phase" ] || die "could not read the rollover phase"
echo "Current rollover phase: $phase"

if [ "$phase" = "not-started" ]; then
  docker compose run --rm --no-deps registrar sync-provider-ds \
    || die "synchronize stable provider DS failed with exit code $?"
  flush_unbound
  assert_validated
  echo "Rollover reset: stable provider state already active."
  exit 0
fi

if [ "$phase" = "baseline" ] || [ "$phase" = "complete" ]; then
  if ( invoke_rollover reconcile && flush_unbound && assert_validated ); then
    echo "Rollover reset: stable state reconciled."
    exit 0
  fi
  echo "The saved phase is not yet stable; completing it safely..."
else
  echo "Completing the interrupted rollover safely..."
fi

NEW_TAG=$(get_rollover_value new-tag)
if [ "$NEW_TAG" -eq 0 ]; then
  invoke_rollover reconcile
  flush_unbound
  assert_validated
  exit 0
fi

# Phase-aware (fix over the .ps1): in new-key-active, acknowledge-published already happened
if [ "$phase" != "new-key-active" ]; then
  docker compose run --rm --no-deps registrar sync-provider-ds \
    || die "publish both provider DS records failed with exit code $?"
  flush_unbound
  assert_validated
  invoke_rollover acknowledge-published
else
  echo "Phase new-key-active: the new key is already published and acknowledged; finishing the withdrawal."
fi

docker compose run --rm --no-deps registrar sync-provider-ds --key-tag "$NEW_TAG" \
  || die "publish only the new provider DS failed with exit code $?"
flush_unbound
assert_validated
invoke_rollover acknowledge-withdrawn
flush_unbound
assert_validated
echo "Rollover reset: transition completed at the new stable key."
