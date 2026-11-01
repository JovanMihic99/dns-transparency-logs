#!/usr/bin/env bash
# Bash port of test-ds-removal.ps1: scenario 7, parent DS removal -> insecure (no AD) and collector HIGH.
# Lab only. Usage: sudo bash lab/test-ds-removal.sh   (needs the lokey-collector container running)
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$LAB/.." && pwd)"
cd "$ROOT"

ZONE="victim.test."
die() { echo "ERROR: $*" >&2; exit 1; }
dc() { docker compose -p lab -f "$LAB/docker-compose.yml" -f "$ROOT/scenarios/ds-removal/docker-compose.yml" --profile tools "$@"; }
run_tool() { dc run --rm --no-deps ds-removal "$1" || die "ds-removal $1 failed"; }
flush() { dc exec -T unbound unbound-control flush_zone "$ZONE" || die "cache flush failed"; }

answer() {  # $1 = expected AD (true|false); always NOERROR and 192.0.2.10
  local out has_ad=false
  out=$(dc exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer) || die "resolver query failed"
  grep -q 'status: NOERROR' <<<"$out" && grep -Eq 'A[[:space:]]+192\.0\.2\.10' <<<"$out" || die "wrong resolver answer:
$out"
  grep -Eq 'flags:.*\bad\b' <<<"$out" && has_ad=true
  [ "$has_ad" = "$1" ] || die "AD expected=$1:
$out"
}

collector_lines() { { docker exec lokey-collector cat /app/data/events.jsonl 2>/dev/null || true; } | wc -l; }

cleanup() {  # like the .ps1 finally block: always restore the DS and re-check
  local rc=$? ok=1
  trap - EXIT
  set +e
  dc run --rm --no-deps ds-removal restore || ok=0
  dc exec -T unbound unbound-control flush_zone "$ZONE" || ok=0
  ( answer true ) || ok=0
  dc exec -T root sh /opt/lab/test-dnssec.sh || ok=0
  [ "$ok" -eq 1 ] || { echo "ERROR: restore incomplete; run: sudo bash lab/reset-ds-removal.sh" >&2; exit 1; }
  exit "$rc"
}
trap cleanup EXIT

START=$(collector_lines)
dc build ds-removal || die "build failed"
run_tool restore; flush; answer true
run_tool remove;  flush; answer false

SEEN=0
DEADLINE=$(( $(date +%s) + 45 ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if { docker exec lokey-collector cat /app/data/events.jsonl 2>/dev/null || true; } | tail -n +"$((START + 1))" | python3 -c '
import sys, json
for line in sys.stdin:
    try: e = json.loads(line)
    except ValueError: continue
    if "DS_ALL_REMOVED" in e["observation"]["changes"] and e["assessment"]["risk"] == "high":
        sys.exit(0)
sys.exit(1)'; then SEEN=1; break; fi
  sleep 1
done
[ "$SEEN" -eq 1 ] || die "collector did not emit HIGH DS_ALL_REMOVED"
echo "PASS: DS removal returned insecure NOERROR/AD=false and collector HIGH."
