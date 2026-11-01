#!/usr/bin/env bash
# Bash port of test-provider-migration.ps1: scenario 5, pre-announced provider migration -> all low risk.
# Lab only. Usage: sudo bash lab/test-provider-migration.sh   (needs the lokey-collector container running)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RESET_REQUIRED=0
die() { echo "ERROR: $*" >&2; exit 1; }
dc() { docker compose -p lab -f "$ROOT/lab/docker-compose.yml" -f "$ROOT/scenarios/provider-migration/docker-compose.yml" --profile tools "$@"; }
event_lines() { { docker exec lokey-collector cat /app/data/events.jsonl 2>/dev/null || true; } ; }

migration() {  # shows output, keeps it in MIG_OUT
  local rc=0
  MIG_OUT=$(dc run --rm --no-deps -T provider-migration "$1") || rc=$?
  MIG_OUT=$(printf '%s\n' "$MIG_OUT" | tr -d '\r')
  printf '%s\n' "$MIG_OUT"
  [ "$rc" -eq 0 ] || die "provider-migration $1 failed"
}

assert_validated_address() {
  local answer
  answer=$(dc exec -T root dig @172.30.0.14 "www.victim.test." A +dnssec +noall +comments +answer) || die "Unbound query failed"
  grep -q 'status: NOERROR' <<<"$answer" && grep -Eq 'flags:.*\bad\b' <<<"$answer" \
    && grep -Eq 'A[[:space:]]+192\.0\.2\.10' <<<"$answer" || die "expected NOERROR, AD=true, and 192.0.2.10:
$answer"
}

assert_collector_events() {  # all three low-risk events after START, within 60 s
  local end=$(( $(date +%s) + 60 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    if event_lines | tail -n +"$((START + 1))" | python3 -c '
import sys, json
ds_added = ns_changed = ds_removed = False
for line in sys.stdin:
    try: e = json.loads(line)
    except ValueError: continue
    ch, risk = e["observation"]["changes"], e["assessment"]["risk"]
    if risk != "low": continue
    ds_added |= "DS_ADDED" in ch
    ns_changed |= "NS_CHANGED" in ch and "DNSKEY_CHANGED" in ch
    ds_removed |= "DS_REMOVED" in ch
sys.exit(0 if ds_added and ns_changed and ds_removed else 1)'; then return 0; fi
    sleep 1
  done
  die "collector did not emit the expected low-risk DS_ADDED, provider switch, and DS_REMOVED events"
}

cleanup() {  # like the .ps1 finally block: always migrate back to the original provider
  local rc=$? ok=1
  trap - EXIT
  set +e
  if [ "$RESET_REQUIRED" -eq 1 ]; then
    echo "Returning through the safe reverse migration..."
    ( migration reset ) || ok=0
    ( migration status && grep -q 'state=1: OLD NS / OLD DS' <<<"$MIG_OUT" ) || ok=0
    ( assert_validated_address ) || ok=0
    [ "$ok" -eq 1 ] || { echo "ERROR: safe reset did not restore the original provider baseline; run: sudo bash lab/reset-provider-migration.sh" >&2; exit 1; }
  fi
  exit "$rc"
}
trap cleanup EXIT

START=$(event_lines | wc -l)
[ "$(docker ps --filter 'name=^/lokey-collector$' --filter 'status=running' --format '{{.Names}}')" = "lokey-collector" ] \
  || die "the collector must be running before the migration test so it can prove pre-announcement observation"

dc build provider-migration || die "could not build the provider-migration image"
dc up -d --no-deps --force-recreate tld || die "could not apply the exact TLD update-policy permission"
dc up -d new-provider || die "could not start the isolated new-provider service"

migration status
grep -q 'state=1: OLD NS / OLD DS' <<<"$MIG_OUT" \
  || die "the shared lab is not at the legitimate provider baseline; no migration was attempted"
assert_validated_address

RESET_REQUIRED=1
migration run
migration status
grep -q 'state=4: NEW NS / NEW DS' <<<"$MIG_OUT" || die "migration did not reach the stable new-provider state"
assert_validated_address
assert_collector_events
echo "PASS: provider migration remained validated and was classified as low risk."
