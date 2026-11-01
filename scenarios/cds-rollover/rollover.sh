#!/usr/bin/env bash
# Bash port of scenarios/cds-rollover/rollover.ps1: legitimate CDS-driven KSK rollover (scenario 4).
# The child publishes signed CDS; cds-sync validates the chain and updates the parent DS.
# Lab only. Usage: sudo bash scenarios/cds-rollover/rollover.sh [observation-delay 0-60, default 2]
#   With a running collector use 25, so each phase lands in its own poll.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE="$REPO_ROOT/lab/docker-compose.yml"
cd "$REPO_ROOT"

DELAY="${1:-2}"
case "$DELAY" in ''|*[!0-9]*) echo "ERROR: delay must be a number 0-60" >&2; exit 1;; esac
[ "$DELAY" -le 60 ] || { echo "ERROR: delay must be 0-60" >&2; exit 1; }

ZONE="victim.test."
PROVIDER_ADDR="192.0.2.10"

die() { echo "ERROR: $*" >&2; exit 1; }
dc() { docker compose -f "$COMPOSE" "$@"; }

run_tool() {  # $1 = service (ksk-rollover|cds-sync), $2 = command: shows output, returns it on stdout
  local out rc=0
  out=$(dc run --rm --no-deps -T "$1" "$2") || rc=$?
  out=$(printf '%s\n' "$out" | tr -d '\r')
  printf '%s\n' "$out" >&2
  [ "$rc" -eq 0 ] || die "$1 $2 failed with exit code $rc"
  printf '%s\n' "$out"
}

get_numeric() {  # $1 = output, $2 = prefix like OLD_TAG=
  local v
  v=$(printf '%s\n' "$1" | grep -E "^$2[0-9]+$" | tail -n 1 | sed "s/^$2//" || true)
  [ -n "$v" ] || die "could not read $2 from rollover output"
  echo "$v"
}

rr_tags() {  # $1 = server, $2 = type: comma list of algorithm 13 / digest 2 key tags, sorted
  local raw
  raw=$(dc exec -T root dig "@$1" "$ZONE" "$2" +short) || die "query $2 from $1 failed with exit code $?"
  printf '%s\n' "$raw" | awk '$2 == 13 && $3 == 2 {print $1}' | sort -n -u | paste -sd, -
}

parent_ns() {
  local raw ns
  raw=$(dc exec -T root dig @172.30.0.11 "$ZONE" NS +noall +answer +authority) \
    || die "query parent NS failed with exit code $?"
  ns=$(printf '%s\n' "$raw" | awk '$4 == "NS" {ns = $5} END {print ns}')
  [ -n "$ns" ] || die "could not parse parent NS from: $raw"
  echo "$ns"
}

assert_tags() {  # $1 = actual comma list, $2 = expected tags (space separated), $3 = label
  local expected
  expected=$(printf '%s\n' $2 | sort -n -u | paste -sd, -)
  [ "$1" = "$expected" ] || die "$3 expected [$expected], found [$1]"
  echo "PASS: $3 has key tag(s) $1."
}

count_ksks() {  # number of 257 3 13 DNSKEYs served by the provider
  local raw
  raw=$(dc exec -T root dig @172.30.0.12 "$ZONE" DNSKEY +short) \
    || die "query child DNSKEY failed with exit code $?"
  printf '%s\n' "$raw" | grep -cE '^257[[:space:]]+3[[:space:]]+13[[:space:]]' || true
}

assert_validated() {  # $1 = phase name
  local answer
  dc exec -T unbound unbound-control flush_zone "$ZONE" || die "flush Unbound during $1 failed with exit code $?"
  answer=$(dc exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer) \
    || die "query Unbound during $1 failed with exit code $?"
  if ! grep -q 'status: NOERROR' <<<"$answer" \
     || ! grep -Eq 'flags:.*\bad\b' <<<"$answer" \
     || ! grep -Eq "A[[:space:]]+${PROVIDER_ADDR//./\\.}" <<<"$answer"; then
    die "Unbound did not return ${PROVIDER_ADDR} with AD=true during $1"
  fi
  echo "PASS: AD=true and provider address during $1."
}

observe() { echo "OBSERVABLE PHASE: $1"; if [ "$DELAY" -gt 0 ]; then sleep "$DELAY"; fi; }

dc build cds-sync || die "build CDS synchronizer failed with exit code $?"
dc up -d || die "start lab failed with exit code $?"

bash "$REPO_ROOT/lab/reset-cds-rollover.sh" || die "establish stable CDS rollover baseline failed with exit code $?"
BASELINE_NS=$(parent_ns)
[ "$BASELINE_NS" = "ns.victim.test." ] || die "unexpected baseline parent NS: $BASELINE_NS"
assert_validated "stable baseline"
run_tool cds-sync validate >/dev/null
observe baseline

BEGIN=$(run_tool ksk-rollover begin)
OLD_TAG=$(get_numeric "$BEGIN" OLD_TAG=)
NEW_TAG=$(get_numeric "$BEGIN" NEW_TAG=)
[ "$OLD_TAG" != "$NEW_TAG" ] || die "BIND did not generate an independent successor key"
[ "$(count_ksks)" -eq 2 ] || die "expected old and new child DNSKEYs after begin"
assert_validated "new KSK publication"
observe new-key-published

run_tool ksk-rollover publish-cds-both >/dev/null
assert_tags "$(rr_tags 172.30.0.12 CDS)" "$OLD_TAG $NEW_TAG" "signed child CDS overlap"
run_tool cds-sync validate >/dev/null
assert_validated "signed old+new CDS publication"
observe cds-old-and-new

run_tool cds-sync sync >/dev/null
assert_tags "$(rr_tags 172.30.0.11 DS)" "$OLD_TAG $NEW_TAG" "parent double-DS overlap"
[ "$(parent_ns)" = "$BASELINE_NS" ] || die "parent NS delegation changed during CDS synchronization"
assert_validated "CDS-driven parent double-DS update"
observe parent-double-ds

IDEMPOTENT=$(run_tool cds-sync sync)
grep -qx 'action=noop' <<<"$IDEMPOTENT" || die "second unchanged CDS sync was not idempotent"
echo "PASS: unchanged CDS sync was an idempotent no-op."

run_tool ksk-rollover acknowledge-published >/dev/null
assert_validated "new DS acknowledgement and key activation"
observe new-key-active

run_tool ksk-rollover publish-cds-new >/dev/null
assert_tags "$(rr_tags 172.30.0.12 CDS)" "$NEW_TAG" "new-only child CDS"
run_tool cds-sync validate >/dev/null
observe cds-new-only

run_tool cds-sync sync >/dev/null
assert_tags "$(rr_tags 172.30.0.11 DS)" "$NEW_TAG" "new-only parent DS"
[ "$(parent_ns)" = "$BASELINE_NS" ] || die "parent NS delegation changed when withdrawing old DS"
assert_validated "CDS-driven old DS withdrawal"
observe old-ds-withdrawn

BEFORE=$(rr_tags 172.30.0.11 DS)
run_tool cds-sync verify-tampered >/dev/null
AFTER=$(rr_tags 172.30.0.11 DS)
[ "$BEFORE" = "$AFTER" ] || die "tampered CDS test changed the parent DS"
echo "PASS: tampered CDS was rejected before UPDATE and parent DS was unchanged."

run_tool ksk-rollover acknowledge-withdrawn >/dev/null
assert_tags "$(rr_tags 172.30.0.11 DS)" "$NEW_TAG" "final parent DS"
[ "$(count_ksks)" -eq 1 ] || die "final child DNSKEY RRset is not new-key-only"
assert_validated "completed CDS rollover"
observe complete

dc exec -T root sh /opt/lab/test-dnssec.sh || die "DNSSEC baseline regression failed with exit code $?"
run_tool ksk-rollover reconcile >/dev/null
echo "PASS: legitimate CDS-driven rollover completed: $OLD_TAG -> $NEW_TAG."
