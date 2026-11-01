#!/usr/bin/env bash
# Bash port of test-zsk-rollover.ps1: legitimate ZSK-only rollover (scenario 1) on an isolated
# split-key provider; KSK, parent DS and NS must stay unchanged. Always resets to the base provider.
# Lab only. Usage: sudo bash lab/test-zsk-rollover.sh [observation-delay 0-60, default 2]
#   With a running collector use 25, so each phase lands in its own poll.
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$LAB/.." && pwd)"
cd "$REPO_ROOT"

DELAY="${1:-2}"
case "$DELAY" in ''|*[!0-9]*) echo "ERROR: delay must be a number 0-60" >&2; exit 1;; esac
[ "$DELAY" -le 60 ] || { echo "ERROR: delay must be 0-60" >&2; exit 1; }

ZONE="victim.test."
PROVIDER_ADDR="192.0.2.10"
SCENARIO_ACTIVE=0
BASELINE_DS=""
BASELINE_NS=""
BASELINE_KSK=""

die() { echo "ERROR: $*" >&2; exit 1; }
base() { docker compose -p lab -f "$LAB/docker-compose.yml" "$@"; }
zsk()  { docker compose -p lab -f "$LAB/docker-compose.yml" -f "$REPO_ROOT/scenarios/zsk-rollover/docker-compose.yml" "$@"; }

invoke_zsk() {  # zsk-rollover <command>: shows its output and returns it on stdout
  local out rc=0
  out=$(zsk run --rm --no-deps -T zsk-rollover "$1") || rc=$?
  out=$(printf '%s\n' "$out" | tr -d '\r')
  printf '%s\n' "$out" >&2
  [ "$rc" -eq 0 ] || die "zsk-rollover $1 failed with exit code $rc"
  printf '%s\n' "$out"
}

parent_ds() {
  base exec -T root dig @172.30.0.11 "$ZONE" DS +short +nosplit || die "query parent DS failed"
}

parent_ns() {
  local raw ns
  raw=$(base exec -T root dig @172.30.0.11 "$ZONE" NS +noall +answer +authority) || die "query parent NS failed"
  ns=$(printf '%s\n' "$raw" | awk '$4 == "NS" {ns = $5} END {print ns}')
  [ -n "$ns" ] || die "could not parse parent NS: $raw"
  echo "$ns"
}

ksk_record() {  # the flag-257 DNSKEY without owner/TTL/class, whitespace collapsed
  local raw rec
  raw=$(base exec -T root dig @172.30.0.12 "$ZONE" DNSKEY +noall +answer +nosplit) || die "query provider KSK DNSKEY failed"
  rec=$(printf '%s\n' "$raw" | grep -E '[[:space:]]DNSKEY[[:space:]]+257[[:space:]]+3[[:space:]]+13[[:space:]]' \
        | sed -E 's/^[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+DNSKEY[[:space:]]+//' | tr -s ' \t' ' ' || true)
  [ -n "$rec" ] || die "provider did not publish a flag-257 DNSKEY"
  echo "$rec"
}

dnskey_counts() {  # prints "<ksk-count> <zsk-count>"
  local lines k z
  lines=$(base exec -T root dig @172.30.0.12 "$ZONE" DNSKEY +short) || die "query provider DNSKEY roles failed"
  k=$(printf '%s\n' "$lines" | grep -cE '^257[[:space:]]+3[[:space:]]+13[[:space:]]' || true)
  z=$(printf '%s\n' "$lines" | grep -cE '^256[[:space:]]+3[[:space:]]+13[[:space:]]' || true)
  echo "$k $z"
}

rrsig_tags() {  # $1 = covered type: space-separated, sorted signer key tags at the provider
  local raw
  raw=$(base exec -T root dig @172.30.0.12 "$ZONE" "$1" +dnssec +noall +answer) || die "query RRSIG($1) failed"
  printf '%s\n' "$raw" | awk -v t="$1" '$4 == "RRSIG" && $5 == t {print $11}' | sort -n -u | tr '\n' ' '
}

has_tag() { [[ " $1 " == *" $2 "* ]]; }

assert_invariants() {  # $1 = phase
  local answer
  [ "$(parent_ds)" = "$BASELINE_DS" ] || die "parent DS changed during $1"
  [ "$(parent_ns)" = "$BASELINE_NS" ] || die "parent NS changed during $1"
  [ "$(ksk_record)" = "$BASELINE_KSK" ] || die "KSK public identity changed during $1"
  base exec -T unbound unbound-control flush_zone "$ZONE" || die "flush Unbound during $1 failed"
  answer=$(base exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer) \
    || die "query Unbound during $1 failed"
  if ! grep -q 'status: NOERROR' <<<"$answer" \
     || ! grep -Eq 'flags:.*\bad\b' <<<"$answer" \
     || ! grep -Eq "A[[:space:]]+${PROVIDER_ADDR//./\\.}" <<<"$answer"; then
    die "Unbound did not return ${PROVIDER_ADDR} with AD=true during $1"
  fi
  echo "PASS: KSK, parent DS/NS, provider address, and AD=true during $1."
}

observe() { echo "OBSERVABLE PHASE: $1"; if [ "$DELAY" -gt 0 ]; then sleep "$DELAY"; fi; }

cleanup() {  # like the .ps1 finally block: always go back to the base provider
  local rc=$?
  trap - EXIT
  if [ "$SCENARIO_ACTIVE" -eq 1 ]; then
    echo "== restoring the base provider (reset-zsk-rollover.sh)"
    bash "$LAB/reset-zsk-rollover.sh" || { echo "ERROR: reset-zsk-rollover.sh failed; run it again by hand" >&2; rc=1; }
  fi
  [ "$rc" -eq 0 ] && echo "All requested ZSK rollover checks passed."
  exit "$rc"
}
trap cleanup EXIT

base up -d || die "start base lab failed"
bash "$LAB/reset-zsk-rollover.sh" || die "reset to the base provider failed"

BASELINE_DS=$(parent_ds)
BASELINE_NS=$(parent_ns)
BASELINE_KSK=$(ksk_record)
[ "$(dnskey_counts)" = "1 0" ] || die "expected the shared baseline to contain one CSK and no separate ZSK"
assert_invariants "CSK baseline"
observe csk-baseline

zsk config --quiet || die "Scenario 1 Compose override is invalid"
zsk run --rm --no-deps zsk-prepare || die "prepare isolated split-key state failed"
zsk up -d --no-deps --force-recreate provider || die "activate isolated split-key provider failed"
SCENARIO_ACTIVE=1

READY=0
for _ in $(seq 1 60); do
  if [ "$( (dnskey_counts) 2>/dev/null || true)" = "1 1" ]; then READY=1; break; fi
  sleep 1
done
[ "$READY" -eq 1 ] || die "split-key provider did not become ready"

invoke_zsk establish-baseline >/dev/null
[ "$(dnskey_counts)" = "1 1" ] || die "split baseline has incorrect DNSKEY roles"
assert_invariants "split-key baseline"
observe split-baseline

BEGIN=$(invoke_zsk begin)
OLD_ZSK=$(printf '%s\n' "$BEGIN" | grep -E '^OLD_ZSK_TAG=[0-9]+$' | tail -n 1 | cut -d= -f2 || true)
NEW_ZSK=$(printf '%s\n' "$BEGIN" | grep -E '^NEW_ZSK_TAG=[0-9]+$' | tail -n 1 | cut -d= -f2 || true)
[ -n "$OLD_ZSK" ] && [ -n "$NEW_ZSK" ] || die "could not read OLD_ZSK_TAG/NEW_ZSK_TAG from begin"
[ "$OLD_ZSK" != "$NEW_ZSK" ] || die "successor ZSK is not independent"
[ "$(dnskey_counts)" = "1 2" ] || die "new-ZSK publication did not produce two ZSKs"
assert_invariants "new ZSK publication"
observe new-zsk-published

invoke_zsk activate >/dev/null
SIGNERS=$(rrsig_tags A)
has_tag "$SIGNERS" "$OLD_ZSK" && has_tag "$SIGNERS" "$NEW_ZSK" \
  || die "apex A RRset does not have the expected old/new ZSK signature overlap (signers: $SIGNERS)"
assert_invariants "ZSK signature transition"
observe zsk-signature-overlap

invoke_zsk retire >/dev/null
SIGNERS=$(rrsig_tags A)
! has_tag "$SIGNERS" "$OLD_ZSK" && has_tag "$SIGNERS" "$NEW_ZSK" \
  || die "ordinary apex signatures did not transition exclusively to the successor ZSK (signers: $SIGNERS)"
assert_invariants "old ZSK retirement and cache-safety hold"
observe old-zsk-retired

invoke_zsk complete >/dev/null
[ "$(dnskey_counts)" = "1 1" ] || die "final DNSKEY RRset is not one KSK plus one ZSK"
SIGNERS=$(rrsig_tags A)
! has_tag "$SIGNERS" "$OLD_ZSK" && has_tag "$SIGNERS" "$NEW_ZSK" \
  || die "final ordinary RRset is not signed exclusively by the successor ZSK (signers: $SIGNERS)"
assert_invariants "completed ZSK rollover"
observe complete

base exec -T root sh /opt/lab/test-dnssec.sh || die "DNSSEC baseline regression in split-key state failed"
echo "PASS: genuine ZSK-only rollover completed: $OLD_ZSK -> $NEW_ZSK; KSK and parent delegation unchanged."
