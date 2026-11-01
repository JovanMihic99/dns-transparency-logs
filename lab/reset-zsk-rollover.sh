#!/usr/bin/env bash
# Bash port of reset-zsk-rollover.ps1: put the original provider (shared provider_state) back after scenario 1.
# Recreates only the provider container from the base compose file; no volume is removed.
# Lab only. Usage: sudo bash lab/reset-zsk-rollover.sh
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB/.."

ZONE="victim.test."
PROVIDER_ADDR="192.0.2.10"

die() { echo "ERROR: $*" >&2; exit 1; }
base() { docker compose -p lab -f "$LAB/docker-compose.yml" "$@"; }

BEFORE_DS=$(base exec -T root dig @172.30.0.11 "$ZONE" DS +short) || die "read parent DS before reset failed"
BEFORE_NS=$(base exec -T root dig @172.30.0.11 "$ZONE" NS +noall +answer +authority) || die "read parent NS before reset failed"

# Recreate only provider from the base definition; this reattaches the untouched provider_state volume.
base up -d --no-deps --force-recreate provider || die "restore base provider service failed with exit code $?"

READY=0
for _ in $(seq 1 60); do
  KEYS=$(base exec -T root dig @172.30.0.12 "$ZONE" DNSKEY +short 2>/dev/null) || KEYS=""
  if [ "$(printf '%s\n' "$KEYS" | grep -cE '^257[[:space:]]+3[[:space:]]+13[[:space:]]' || true)" -eq 1 ]; then
    READY=1
    break
  fi
  sleep 1
done
[ "$READY" -eq 1 ] || die "base provider did not become ready after reset"

AFTER_DS=$(base exec -T root dig @172.30.0.11 "$ZONE" DS +short) || die "read parent DS after reset failed"
AFTER_NS=$(base exec -T root dig @172.30.0.11 "$ZONE" NS +noall +answer +authority) || die "read parent NS after reset failed"
[ "$AFTER_DS" = "$BEFORE_DS" ] || die "parent DS changed while resetting the ZSK scenario"
[ "$AFTER_NS" = "$BEFORE_NS" ] || die "parent NS changed while resetting the ZSK scenario"

base exec -T unbound unbound-control flush_zone "$ZONE" || die "flush Unbound after provider reset failed"
ANSWER=$(base exec -T root dig @172.30.0.14 "www.${ZONE}" A +dnssec +noall +comments +answer) \
  || die "validate restored provider through Unbound failed"
if ! grep -q 'status: NOERROR' <<<"$ANSWER" \
   || ! grep -Eq 'flags:.*\bad\b' <<<"$ANSWER" \
   || ! grep -Eq "A[[:space:]]+${PROVIDER_ADDR//./\\.}" <<<"$ANSWER"; then
  die "restored base provider did not return ${PROVIDER_ADDR} with AD=true"
fi
echo "ZSK reset passed: original provider_state restored; parent DS/NS unchanged; AD=true."
