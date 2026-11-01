#!/usr/bin/env bash
# Bash port of test-dnssec-negative.ps1: a deliberately wrong DS must make validation fail
# (SERVFAIL, no AD); the correct DS is always restored afterwards.
# Lab only (.test, isolated Docker network). Usage: sudo bash lab/test-dnssec-negative.sh
set -euo pipefail
cd "$(dirname "$0")"

ZONE="victim.test."
RESTORE_NEEDED=0
TEST_PASSED=0
CORRECT_DS=""

die() { echo "ERROR: $*" >&2; exit 1; }

normalize_ds() {  # "tag alg type digest parts..." -> "tag alg type digest"; fails if unparseable
  set -- $1
  [ "$#" -ge 4 ] || return 1
  local tag=$1 alg=$2 typ=$3
  shift 3
  echo "$tag $alg $typ $(printf '%s' "$@")"
}

read_parent_ds() {
  docker compose exec -T root dig @172.30.0.11 "$ZONE" DS +short
}

nsupdate_ds() {  # $1 = DS rdata
  docker compose exec -T tld nsupdate -k /opt/lab/registrar.key <<EOF || die "nsupdate failed with exit code $?"
server 172.30.0.11 53
zone test.
update delete $ZONE DS
update add $ZONE 30 IN DS $1
send
EOF
}

wait_for_ds() {  # $1 = expected normalized DS; up to 30 tries
  local observed
  for _ in $(seq 1 30); do
    observed=$(normalize_ds "$(read_parent_ds 2>/dev/null || true)" || true)
    [ "$observed" = "$1" ] && return 0
    sleep 1
  done
  die "timed out waiting for the test TLD to publish the requested DS"
}

cleanup() {  # like the .ps1 finally block: always put the correct DS back
  local rc=$? ok=1
  trap - EXIT
  set +e
  if [ "$RESTORE_NEEDED" -eq 1 ]; then
    echo "Restoring the correct victim.test DS record..."
    ( nsupdate_ds "$CORRECT_DS" && wait_for_ds "$CORRECT_DS" ) || ok=0
    docker compose restart unbound || ok=0
    docker compose exec -T root sh /opt/lab/test-dnssec.sh || ok=0
    [ "$ok" -eq 1 ] || echo "ERROR: restore incomplete; check: docker compose run --rm --no-deps registrar status" >&2
  fi
  if [ "$TEST_PASSED" -eq 1 ] && [ "$ok" -eq 1 ] && [ "$rc" -eq 0 ]; then exit 0; fi
  exit 1
}
trap cleanup EXIT

RAW_DS=$(read_parent_ds) || die "read parent DS failed"
[ -n "$RAW_DS" ] || die "the working victim.test DS record was not found"
[ "$(printf '%s\n' "$RAW_DS" | wc -l)" -eq 1 ] || die "expected exactly one victim.test DS record"
CORRECT_DS=$(normalize_ds "$RAW_DS") || die "could not parse DS record: $RAW_DS"

LAST="${CORRECT_DS: -1}"
if [ "$LAST" = "0" ]; then REPLACEMENT=1; else REPLACEMENT=0; fi
BAD_DS="${CORRECT_DS%?}$REPLACEMENT"

echo "Installing a deliberately incorrect victim.test DS record..."
RESTORE_NEEDED=1
nsupdate_ds "$BAD_DS"
wait_for_ds "$BAD_DS"
docker compose restart unbound || die "could not restart Unbound to clear its cache"

RENDERED=$(docker compose exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments || true)
grep -q 'status: SERVFAIL' <<<"$RENDERED" \
  || die "expected SERVFAIL with the incorrect DS, but received:
$RENDERED"
! grep -Eq 'flags:.*\bad\b' <<<"$RENDERED" || die "the invalid response unexpectedly contained the AD flag"
echo "PASS: the incorrect DS caused DNSSEC validation failure (SERVFAIL, no AD flag)."
TEST_PASSED=1
