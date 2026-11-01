#!/usr/bin/env bash
# Bash port of test-unsigned-ns-change.ps1: scenario 8, NS-only change on an unsigned domain -> collector MEDIUM.
# Lab only. Usage: sudo bash lab/test-unsigned-ns-change.sh   (needs the lokey-collector container running)
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$LAB/.." && pwd)"
cd "$ROOT"

ZONE="victim.test."
PREPARED=0
die() { echo "ERROR: $*" >&2; exit 1; }
dc_base() { docker compose -p lab -f "$LAB/docker-compose.yml" "$@"; }
dc_all()  { docker compose -p lab -f "$LAB/docker-compose.yml" -f "$ROOT/scenarios/unsigned-ns-change/docker-compose.yml" --profile tools "$@"; }
tool()    { dc_all run --rm --no-deps unsigned-change "$1" || die "unsigned-change $1 failed"; }
flush()   { dc_base exec -T unbound unbound-control flush_zone "$ZONE" || die "flush failed"; }

answer() {  # $1 = expected address, $2 = expected AD (true|false)
  local o has_ad=false
  o=$(dc_base exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer) || die "resolver query failed"
  grep -q 'status: NOERROR' <<<"$o" && grep -Eq "A[[:space:]]+${1//./\\.}" <<<"$o" || die "bad answer (expected $1):
$o"
  grep -Eq 'flags:.*\bad\b' <<<"$o" && has_ad=true
  [ "$has_ad" = "$2" ] || die "wrong AD expectation (expected $2):
$o"
}

wait_answering() {  # $1 = server, $2 = dig args..., last arg = grep pattern; up to 30 s (readiness, not in the .ps1)
  local server="$1" pattern="${*: -1}" args=("${@:2:$#-2}")
  for _ in $(seq 1 30); do
    dc_base exec -T root dig "@$server" "${args[@]}" +short 2>/dev/null | grep -q "$pattern" && return 0
    sleep 1
  done
  die "$server did not answer as expected"
}

state_check() {  # $1 = unsigned | signed-nods: prints the collector's observed_at if its state matches
  { docker exec lokey-collector cat /app/data/state.json 2>/dev/null || true; } | python3 -c '
import sys, json
mode = sys.argv[1]
try:
    s = json.load(sys.stdin)["snapshots"]["victim.test"]
except Exception:
    sys.exit(0)
if s["ns"] == ["ns.victim.test."] and not s["ds"]:
    if (mode == "unsigned" and not s["dnskey"]) or (mode == "signed-nods" and s["dnskey"]):
        print(s["observed_at"])' "$1"
}

wait_unsigned_old() {  # two distinct collector polls of the unsigned old provider
  local end=$(( $(date +%s) + 45 )) seen="" t
  while [ "$(date +%s)" -lt "$end" ]; do
    t=$(state_check unsigned)
    if [ -n "$t" ] && [[ " $seen " != *" $t "* ]]; then seen="$seen $t"; fi
    [ "$(wc -w <<<"$seen")" -ge 2 ] && return 0
    sleep 1
  done
  die "collector did not establish two unsigned old-provider snapshots"
}

wait_signed_old_nods() {
  local end=$(( $(date +%s) + 45 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    [ -n "$(state_check signed-nods)" ] && return 0
    sleep 1
  done
  die "collector did not observe the restored signed provider before DS restoration"
}

cleanup() {  # like the .ps1 finally block; always restores the DS even if an earlier step failed
  local rc=$? ok=1
  trap - EXIT
  set +e
  if [ "$PREPARED" -eq 1 ]; then
    ( tool reverse && flush && wait_unsigned_old ) || echo "WARNING: reverse step incomplete; continuing the restore" >&2
    dc_base up -d --no-deps --force-recreate provider || ok=0
    for _ in $(seq 1 30); do dc_base exec -T root dig @172.30.0.12 "$ZONE" DNSKEY +short >/dev/null 2>&1 && break; sleep 1; done
    ( wait_signed_old_nods ) || ok=0
    ( tool restore-ds ) || ok=0
    dc_base exec -T unbound unbound-control flush_zone "$ZONE" || ok=0
    ( answer 192.0.2.10 true ) || ok=0
    dc_base exec -T root sh /opt/lab/test-dnssec.sh || ok=0
    [ "$ok" -eq 1 ] || { echo "ERROR: restore incomplete; run: sudo bash lab/reset-unsigned-ns-change.sh" >&2; exit 1; }
  fi
  exit "$rc"
}
trap cleanup EXIT

dc_all build unsigned-change || die "build failed"
dc_all up -d --no-deps --force-recreate tld || die "recreate tld failed"
wait_answering 172.30.0.11 test. SOA 'test'
tool remove-ds
PREPARED=1
flush
answer 192.0.2.10 false

dc_all up -d --no-deps --force-recreate provider unsigned-new || die "unsigned authorities failed"
wait_answering 172.30.0.12 "www.${ZONE}" A '192\.0\.2\.10'
wait_answering 172.30.0.17 "www.${ZONE}" A '192\.0\.2\.66'
flush
answer 192.0.2.10 false
wait_unsigned_old

START=$({ docker exec lokey-collector cat /app/data/events.jsonl 2>/dev/null || true; } | wc -l)
tool switch
flush
answer 192.0.2.66 false

PASS=0
END=$(( $(date +%s) + 45 ))
while [ "$(date +%s)" -lt "$END" ]; do
  if { docker exec lokey-collector cat /app/data/events.jsonl 2>/dev/null || true; } | tail -n +"$((START + 1))" | python3 -c '
import sys, json
for line in sys.stdin:
    try: e = json.loads(line)
    except ValueError: continue
    if e["observation"]["changes"] == ["NS_CHANGED"] and e["assessment"]["risk"] == "medium":
        sys.exit(0)
sys.exit(1)'; then PASS=1; break; fi
  sleep 1
done
[ "$PASS" -eq 1 ] || die "collector did not emit exactly NS_CHANGED at MEDIUM"
echo "PASS: unsigned NS-only change returned 192.0.2.66, AD=false, collector MEDIUM."
