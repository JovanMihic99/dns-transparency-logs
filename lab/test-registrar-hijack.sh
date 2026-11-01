#!/usr/bin/env bash
# Bash port of test-registrar-hijack.ps1: baseline -> signed registrar hijack -> restore regression.
# Lab only (.test, isolated Docker network). Usage: sudo bash lab/test-registrar-hijack.sh
set -euo pipefail
cd "$(dirname "$0")"

ZONE="victim.test."
RESTORE_REQUIRED=0
SCENARIO_PASSED=0

die() { echo "ERROR: $*" >&2; exit 1; }

registrar() {
  docker compose run --rm --no-deps registrar "$1" || die "registrar $1 failed with exit code $?"
}

child_ds() {  # $1 = server: DS derived from its DNSKEY, normalized "tag alg type digest"
  local line
  line=$(docker compose exec -T root sh -c "dig @$1 $ZONE DNSKEY +noall +answer | dnssec-dsfromkey -2 -f - $ZONE" | head -n 1) \
    || die "derive child DS failed"
  set -- $line   # name IN DS tag alg type digest...
  [ "$#" -ge 7 ] || die "could not parse derived DS: $line"
  shift 3
  local tag=$1 alg=$2 typ=$3
  shift 3
  echo "$tag $alg $typ $(printf '%s' "$@")"
}

parent_ds() {
  local line
  line=$(docker compose exec -T root dig @172.30.0.11 "$ZONE" DS +short | head -n 1) || die "read parent DS failed"
  set -- $line
  [ "$#" -ge 4 ] || die "could not parse DS record: $line"
  local tag=$1 alg=$2 typ=$3
  shift 3
  echo "$tag $alg $typ $(printf '%s' "$@")"
}

parent_ns() {  # last field of the referral, like the .ps1
  local out
  out=$(docker compose exec -T root dig @172.30.0.11 "$ZONE" NS +noall +answer +authority) || die "read parent NS failed"
  awk 'NF {last = $NF; n = NF} END {if (n < 5) exit 1; print last}' <<<"$out" \
    || die "could not parse parent NS record: $out"
}

assert_direct_answer() {  # $1 = authoritative server, $2 = expected address
  local answer
  answer=$(docker compose exec -T root dig "@$1" "www.${ZONE}" A +short) || die "direct query to $1 failed"
  [ "$answer" = "$2" ] || die "expected $2 from $1, got '$answer'"
  echo "PASS: authoritative server $1 returns $2."
}

assert_signed_attacker() {
  local answer
  answer=$(docker compose exec -T root dig @172.30.0.13 "$ZONE" DNSKEY +dnssec +noall +answer) \
    || die "attacker DNSKEY query failed"
  grep -Eq '[[:space:]]DNSKEY[[:space:]]' <<<"$answer" || die "attacker does not publish DNSKEY"
  grep -Eq '[[:space:]]RRSIG[[:space:]]+DNSKEY[[:space:]]' <<<"$answer" || die "attacker DNSKEY RRset is not signed"
  echo "PASS: attacker publishes DNSKEY and an RRSIG over DNSKEY."
}

restart_unbound() {
  docker compose restart unbound || die "restart Unbound failed with exit code $?"
}

assert_validated_answer() {  # $1 = expected address; up to 30 tries, 1 s apart
  local rendered
  for _ in $(seq 1 30); do
    rendered=$(docker compose exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer 2>/dev/null || true)
    if grep -q 'status: NOERROR' <<<"$rendered" \
       && grep -Eq 'flags:.*\bad\b' <<<"$rendered" \
       && grep -Eq "A[[:space:]]+${1//./\\.}" <<<"$rendered"; then
      echo "PASS: Unbound validates $1 and returns AD."
      return 0
    fi
    sleep 1
  done
  die "Unbound did not return validated address $1 with AD"
}

cleanup() {  # like the .ps1 finally block: always restore and re-check the baseline
  local rc=$? ok=1
  trap - EXIT
  set +e
  if [ "$RESTORE_REQUIRED" -eq 1 ]; then
    echo "Restoring the legitimate provider delegation..."
    docker compose run --rm --no-deps registrar restore || ok=0
  fi
  docker compose restart unbound || ok=0
  ( assert_validated_answer 192.0.2.10 ) || ok=0
  docker compose exec -T root sh /opt/lab/test-dnssec.sh || ok=0
  if [ "$SCENARIO_PASSED" -eq 1 ] && [ "$ok" -eq 1 ] && [ "$rc" -eq 0 ]; then
    echo "All registrar baseline -> hijack -> restore regression checks passed."
    exit 0
  fi
  [ "$ok" -eq 1 ] || echo "ERROR: cleanup did not fully restore the lab; check: docker compose run --rm --no-deps registrar status" >&2
  exit 1
}
trap cleanup EXIT

docker compose build registrar || die "build registrar image failed with exit code $?"
docker compose up -d || die "start DNS lab failed with exit code $?"

assert_direct_answer 172.30.0.12 192.0.2.10
assert_direct_answer 172.30.0.13 192.0.2.66
assert_signed_attacker

ATTACKER_BEFORE=$(child_ds 172.30.0.13)
docker compose restart attacker || die "restart attacker failed with exit code $?"
ATTACKER_AFTER=""
for _ in $(seq 1 30); do
  ATTACKER_AFTER=$( (child_ds 172.30.0.13) 2>/dev/null || true )
  [ "$ATTACKER_AFTER" = "$ATTACKER_BEFORE" ] && break
  sleep 1
done
[ "$ATTACKER_AFTER" = "$ATTACKER_BEFORE" ] || die "attacker DNSSEC identity changed after restart"
echo "PASS: attacker DNSSEC identity survives restart."

registrar restore
restart_unbound
assert_validated_answer 192.0.2.10
registrar status

registrar unauthorized-test

RESTORE_REQUIRED=1
registrar hijack
NS_NOW=$(parent_ns)
[ "$NS_NOW" = "ns.attacker.test." ] || die "hijacked NS is '$NS_NOW', expected ns.attacker.test."
[ "$(parent_ds)" = "$(child_ds 172.30.0.13)" ] || die "published attacker DS does not match attacker DNSKEY"
echo "PASS: parent NS and DS match the signed attacker zone."
restart_unbound
assert_validated_answer 192.0.2.66
registrar status

SCENARIO_PASSED=1
