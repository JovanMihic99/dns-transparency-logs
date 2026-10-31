# Scenario 1: legitimate ZSK-only rollover

This scenario gives `victim.test.` separate KSK and ZSK roles without changing
the shared provider's CSK policy or signing state. It uses the normal `lab`
Compose project, the existing `dns_lab` network, service name `provider`, and
provider address `172.30.0.12`.

## Isolation and trust continuity

`zsk-prepare` reads the shared `provider_state` volume **read-only**. It selects
the flag-257 key that derives the current parent DS, copies only that key's
public/private files into `lab_zsk_provider_state`, and generates an independent
flag-256 ZSK. It does not copy BIND policy state and never writes to or deletes
the shared volume.

The replacement provider uses BIND 9.18 legacy `auto-dnssec maintain` only in
this isolated volume. `dnssec-dnskey-kskonly yes` makes the retained flag-257
key sign DNSKEY, CDS, and CDNSKEY while the flag-256 keys sign ordinary zone
RRsets. The parent DS therefore continues to authenticate the same public KSK.
The shared CSK policy remains unchanged for Scenarios 2 and 4.

## Rollover phases

1. `split-baseline`: one unchanged KSK and one ZSK; ordinary data is signed by
   the ZSK.
2. `new-zsk-published`: old and new ZSK DNSKEYs are published, but the old ZSK
   still signs ordinary data.
3. `zsk-signature-overlap`: ordinary RRsets have successor signatures while
   the predecessor still overlaps.
4. `old-zsk-retired`: all ordinary predecessor signatures are gone, but its
   DNSKEY remains published for cache safety.
5. `complete`: after the measured maximum authoritative/DNSKEY TTL plus a
   safety margin, only the successor ZSK remains.

Every phase checks the exact parent DS, parent NS, KSK identity, DNSKEY RRSIG
signer, address `192.0.2.10`, and Unbound `AD=true`. The controller polls BIND's
live DNSKEY and signature state with bounded waits. `TYPE65534` is BIND's
private key-management RR and is deliberately not treated as ordinary zone
content.

## Run the automated test

From the repository root in Windows PowerShell:

```powershell
docker compose -p lab -f .\lab\docker-compose.yml up -d
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-zsk-rollover.ps1
```

For a faster run without collector observation pauses:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-zsk-rollover.ps1 `
  -ObservationDelaySeconds 0
```

Run existing scenario regressions separately; each changes the shared CSK and
its parent DS by design, while Scenario 1 restores that shared baseline:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-ksk-rollover.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-cds-rollover.ps1 `
  -ObservationDelaySeconds 0 -SkipExistingScenarioRegressions
```

Use a nonzero observation delay if the collector needs time to sample each
phase. The controller also writes phase observations to
`lab_zsk_provider_state`; inspect them while the experimental provider is live:

```powershell
$Base = @('-p','lab','-f','.\lab\docker-compose.yml')
$Zsk = @('-f','.\scenarios\zsk-rollover\docker-compose.yml')
docker compose @Base @Zsk run --rm --no-deps zsk-rollover status
docker compose @Base @Zsk run --rm --no-deps zsk-rollover events
```

## Safe reset and recovery

If a run is interrupted, restore only the original provider definition:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\reset-zsk-rollover.ps1
```

This recreates only the `provider` container from the base Compose file,
reattaches the untouched `provider_state`, verifies unchanged parent DS/NS, and
checks the restored answer through Unbound. It does not remove any volume or
restart other authoritative services.

A resolver may still cache the experimental DNSKEY RRset during reset. That
RRset contains the same flag-257 key as the restored CSK baseline. The restored
CSK signs both DNSKEY and ordinary data with that trusted key, so the cached
experimental RRset can validate the restored response instead of making it
bogus. The reset additionally flushes only the synthetic `victim.test.` cache
for deterministic lab verification.

Do not use `docker compose down -v`, and do not delete either provider volume.
After recovery, rerun the test; preparation creates a new isolated run while
preserving previous scenario state.

## Lab-only limitation

The 30-second DNSKEY and ordinary record TTLs make the transition observable
within hackathon time. Production ZSK rollovers require timing based on the
zone's real TTLs, signature validity/refresh periods, propagation delay, and
resolver behavior. The legacy mechanism is intentionally confined to this
scenario because the shared CSK scenarios use BIND's DNSSEC policy engine.
