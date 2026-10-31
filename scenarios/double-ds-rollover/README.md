# Scenario 3: legitimate Double-DS KSK rollover

This scenario drives the existing BIND CSK rollover and mock registrar through
an independently observable parent-side Double-DS transition. It does not
change the shared DNSSEC policy, registrar, or Scenario 2/4 controllers.

## Trust-preserving phases

1. **Baseline:** child DNSKEY and parent DS contain OLD only.
2. **Successor publication:** the authenticated child DNSKEY RRset contains OLD
   and NEW while the parent still contains OLD only.
3. **Double-DS overlap:** the parent contains the exact SHA-256 DS RDATA derived
   from both authenticated child keys.
4. **Successor activation:** BIND acknowledges NEW's DS; NEW signs DNSKEY.
5. **OLD DS withdrawal:** the parent contains NEW only while both child keys
   remain published.
6. **Completion:** NEW signs every authoritative RRset, the measured DNSKEY/DS
   TTL safety window passes, and only then is OLD retired.

Every phase checks the unchanged `ns.victim.test.` delegation and a fresh
Unbound response containing `NOERROR`, `AD`, and `192.0.2.10`. DS values are
compared as exact canonical RDATA after deriving them from the
Unbound-authenticated DNSKEY response with `dnssec-dsfromkey`.

The observation duration can extend collector-visible phases, but never
shortens the TTL-derived safety holds.

## Run and test (Windows PowerShell)

From the repository root:

```powershell
docker compose -f .\lab\docker-compose.yml up -d
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-double-ds-rollover.ps1 -ObservationDurationSeconds 5
```

Use a larger observation duration (up to 300 seconds) when a slow collector
needs more time:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-double-ds-rollover.ps1 -ObservationDurationSeconds 15
```

## Safe recovery

If a run is interrupted, do not delete volumes or keys and do not restore the
retired predecessor. Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\reset-double-ds-rollover.ps1 -ObservationDurationSeconds 5
```

Recovery reads saved metadata, BIND KASP state, authenticated child DNSKEY and
RRSIG data, exact parent DS RDATA, parent NS, and Unbound AD state before every
mutation. An ambiguous combination stops with diagnostics. A partially
completed `acknowledge-withdrawn` is retried only after NEW signs every
authoritative RRset and the measured TTL plus propagation margin has passed.

Inspect the shared controller's observations without changing state:

```powershell
docker compose -f .\lab\docker-compose.yml run --rm ksk-rollover status
docker compose -f .\lab\docker-compose.yml run --rm ksk-rollover events
```

## Lab timing limitation

The 30-second DNS TTLs are intentionally compressed. BIND's 300-second
signature refresh remains asynchronous. Scenario 3 polls real RRSIGs and KASP
state for that interval plus the observed TTL and a margin; elapsed time alone
never authorizes retirement. These timings are suitable only for this isolated
synthetic lab, not production DNSSEC operations.
