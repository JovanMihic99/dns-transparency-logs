#!/usr/bin/env bash
# LoKey live scenario test: run lab scenarios against the running collector and check
# each verdict against spec section 8. Lab only (.test, isolated Docker network).
# Needs: lab, log and collector containers running; sudo for docker.
# Usage (repo root): bash tests/live_scenarios.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab"; COL="$ROOT/collector"
PRE="$COL/data/preannouncements.json"
WAIT=25                                  # >= 2 collector polls (10 s each)
RESULTS="$ROOT/live_results.txt"; : > "$RESULTS"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

reg() {  # registrar command, --no-deps: Unbound may be briefly unhealthy after a swap
  (cd "$LAB" && sudo docker compose run --rm --no-deps registrar "$@") 2>&1 \
    | grep -E "Parent delegation|ERROR|Error|error|failed" || true
}

events_since() {  # one line per collector event: risk <TAB> changes <TAB> reasons
  (cd "$COL" && sudo docker compose logs --no-log-prefix --since "$1") 2>/dev/null | python3 -c '
import sys, json
for line in sys.stdin:
    line = line.strip()
    if line.startswith("{"):
        e = json.loads(line); a = e["assessment"]
        print(a["risk"] + "\t" + ",".join(e["observation"]["changes"]) + "\t" + " | ".join(a["reasons"]))'
}

check() {  # name, start time, expected risks (comma list, "" = no event), required reason text
  local name="$1" start="$2" want="$3" reason="${4:-}" got risks ok=PASS
  got=$(events_since "$start")
  risks=$(printf '%s\n' "$got" | cut -f1 | grep -v '^$' | paste -sd, -)
  [ "$risks" = "$want" ] || ok=FAIL
  if [ -n "$reason" ] && ! printf '%s' "$got" | grep -qF "$reason"; then ok=FAIL; fi
  printf '%-4s %-34s expected=%-6s got=%s\n' "$ok" "$name" "${want:-none}" "${risks:-none}" | tee -a "$RESULTS"
  [ "$ok" = PASS ] || printf '%s\n' "$got" | sed 's/^/       /' | tee -a "$RESULTS"
}

reset_collector() {  # fresh baseline; the lab must be on the provider
  (cd "$COL" && sudo docker compose stop >/dev/null 2>&1)
  rm -f "$COL/data/state.json" "$PRE"
  (cd "$COL" && sudo docker compose start >/dev/null 2>&1)
  for _ in $(seq 1 12); do
    (cd "$COL" && sudo docker compose logs --no-log-prefix --since 40s) 2>/dev/null \
      | grep -q '^\[baseline\]' && return 0
    sleep 5
  done
  echo "collector did not report a baseline"; exit 1
}

cleanup() { rm -f "$PRE"; echo "== cleanup: restoring the provider"; reg restore; }
trap cleanup EXIT

sudo -v
echo "== preparing: lab on the provider, fresh collector baseline"
reg restore
PROV_DS=$( (cd "$LAB" && sudo docker compose run --rm --no-deps registrar status) 2>/dev/null \
  | sed -n 's/^parent DS: //p' | head -1)
[ -n "$PROV_DS" ] || { echo "cannot read the provider DS"; exit 1; }
echo "provider DS: $PROV_DS"
reset_collector

echo "== running scenarios (about 2.5 minutes)"
T=$(now); sleep "$WAIT"
check "0  quiet: no change -> no event" "$T" ""

T=$(now); reg hijack; sleep "$WAIT"
check "6  registrar hijack" "$T" "high" "DS replaced with no trail"

cat > "$PRE" <<EOF
[{"domain": "victim.test", "new_ns": ["ns.victim.test."], "new_ds": ["$PROV_DS"],
  "valid_until": "$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)"}]
EOF
T=$(now); reg restore; sleep "$WAIT"
check "5b pre-announced change" "$T" "low" "matches a pre-announcement"
rm -f "$PRE"

T=$(now); reg hijack; sleep "$WAIT"
check "6b re-hijack (v1.1 quarantine)" "$T" "high" "DS replaced with no trail"

T=$(now); reg restore; sleep "$WAIT"
check "5a unannounced NS+DS change" "$T" "high" "not pre-announced"

echo "== summary: $(grep -c '^PASS' "$RESULTS") passed, $(grep -c '^FAIL' "$RESULTS") failed (details in /tmp/lokey_live_results.txt)"
