#!/usr/bin/env bash
# Bash port of test-ksk-rollover.ps1: run the legitimate double-KSK rollover (scenario 2)
# end to end and check that Unbound validates (AD) after every step.
# Lab only. Usage: sudo bash lab/test-ksk-rollover.sh [pause-seconds]
#   pause-seconds (default 0): wait between steps so a running collector sees each one (use 25)
set -euo pipefail
cd "$(dirname "$0")"

ZONE="victim.test."
PROVIDER_ADDR="192.0.2.10"
PAUSE="${1:-0}"
ROLLOVER_STARTED=0

die() { echo "ERROR: $*" >&2; exit 1; }

pause() {
  if [ "$PAUSE" -gt 0 ]; then echo "(waiting ${PAUSE}s so the collector sees this step)"; sleep "$PAUSE"; fi
}

invoke_rollover() {  # ksk-rollover <command>: shows its output and returns it on stdout
  local out rc=0
  out=$(docker compose run --rm --no-deps -T ksk-rollover "$1") || rc=$?
  out=$(printf '%s\n' "$out" | tr -d '\r')
  printf '%s\n' "$out" >&2
  [ "$rc" -eq 0 ] || die "ksk-rollover $1 failed with exit code $rc"
  printf '%s\n' "$out"
}

flush_unbound() {
  docker compose exec -T unbound unbound-control flush_zone "$ZONE" \
    || die "flush Unbound $ZONE cache failed with exit code $?"
}

assert_validated() {  # $1 = phase name; flush, then NOERROR + AD + provider address
  local answer
  flush_unbound
  answer=$(docker compose exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer) \
    || die "query Unbound during $1 failed with exit code $?"
  if ! grep -q 'status: NOERROR' <<<"$answer" \
     || ! grep -Eq 'flags:.*\bad\b' <<<"$answer" \
     || ! grep -Eq "A[[:space:]]+${PROVIDER_ADDR//./\\.}" <<<"$answer"; then
    die "Unbound did not return ${PROVIDER_ADDR} with AD=true during $1"
  fi
  echo "PASS: Unbound returned AD=true during $1."
}

cleanup() {  # like the .ps1 finally block: always leave a stable rollover state
  local rc=$?
  if [ "$ROLLOVER_STARTED" -eq 1 ]; then
    echo "== restoring a stable rollover state (reset-ksk-rollover.sh)"
    bash ./reset-ksk-rollover.sh || echo "WARNING: reset-ksk-rollover.sh failed; run it again by hand" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT

docker compose build registrar || die "build registrar failed with exit code $?"
docker compose up -d || die "start lab failed with exit code $?"

# The bind-mounted Unbound configuration may have changed without a container recreation.
docker compose kill -s HUP unbound || die "reload Unbound configuration failed with exit code $?"
sleep 2

bash ./reset-ksk-rollover.sh || die "establish stable rollover baseline failed with exit code $?"
assert_validated "baseline"
pause

BEGIN_OUT=$(invoke_rollover begin)
ROLLOVER_STARTED=1
OLD_TAG=$(printf '%s\n' "$BEGIN_OUT" | grep -E '^OLD_TAG=[0-9]+$' | tail -n 1 | cut -d= -f2 || true)
NEW_TAG=$(printf '%s\n' "$BEGIN_OUT" | grep -E '^NEW_TAG=[0-9]+$' | tail -n 1 | cut -d= -f2 || true)
[ -n "$OLD_TAG" ] && [ -n "$NEW_TAG" ] || die "could not read OLD_TAG/NEW_TAG from ksk-rollover begin"
[ "$OLD_TAG" != "$NEW_TAG" ] || die "BIND did not generate an independent successor key"
assert_validated "new-key prepublication with old parent DS"
pause

docker compose run --rm --no-deps registrar sync-provider-ds \
  || die "publish double provider DS set failed with exit code $?"
assert_validated "double DNSKEY and double DS state"
pause

invoke_rollover acknowledge-published >/dev/null
assert_validated "new-key activation"

docker compose run --rm --no-deps registrar sync-provider-ds --key-tag "$NEW_TAG" \
  || die "withdraw old provider DS failed with exit code $?"
assert_validated "new-only parent DS before old-key retirement"
pause

invoke_rollover acknowledge-withdrawn >/dev/null
assert_validated "completed rollover"

docker compose exec -T root sh /opt/lab/test-dnssec.sh || die "DNSSEC baseline regression failed with exit code $?"
echo "All legitimate Double-KSK rollover checks passed: $OLD_TAG -> $NEW_TAG."
