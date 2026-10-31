# Scenario 4: legitimate CDS-driven KSK rollover

This scenario keeps `victim.test.` continuously secure while the child asks its
parent to replace the DS RRset by publishing authenticated CDS records. It runs
only inside the private Docker network.

## Architecture and trust checks

`cds-sync` queries the authoritative servers directly. Before it is allowed to
send an update, it performs these checks with dnspython's DNSSEC validator:

1. The live private-root DNSKEY RRset must contain and be signed by the key in
   the persistent lab root trust-anchor file.
2. The signed root DS for `test.` must authenticate the `test.` DNSKEY RRset.
3. The signed `test.` DS for `victim.test.` must authenticate the child's
   existing DNSKEY RRset.
4. The authenticated child DNSKEY RRset must validate the CDS RRSIG.
5. Every CDS must use supported algorithm 13 and SHA-256 digest type 2, match an
   eligible published SEP DNSKEY, and have the correct digest.

The synchronizer rejects missing records or signatures, malformed or unsupported
data, mismatched keys and digests, unauthenticated children, empty CDS answers,
and RFC 8078 deletion signaling. It never treats an empty response as permission
to remove DS. After validation, it changes only the parent DS through the
existing `mock-registrar.` TSIG key and verifies the signed result. The parent NS
delegation is not included in the UPDATE. An unchanged CDS/DS set is a no-op.

DNSKEY is the child's public signing key. DS is the parent's digest-based pointer
to that key. CDS has DS-shaped contents but is published and signed by the child
as a request to change the parent's DS; it is not trusted until the current
DNSSEC chain and the CDS signature have both been validated.

## Run from Windows PowerShell

From the repository root:

```powershell
docker compose -f lab/docker-compose.yml build cds-sync
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml run --rm cds-sync validate
docker compose -f lab/docker-compose.yml run --rm cds-sync sync
powershell -NoProfile -ExecutionPolicy Bypass -File .\scenarios\cds-rollover\rollover.ps1
```

The direct `sync` command is safe to repeat. With unchanged CDS, it prints
`action=noop` and does not send DNS UPDATE.

Run the full regression suite, including Scenario 2 and registrar hijack:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-cds-rollover.ps1
```

For a quicker Scenario 4-only test with no collector observation delays:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-cds-rollover.ps1 -ObservationDelaySeconds 0 -SkipExistingScenarioRegressions
```

The default two-second phase delay lets a collector polling every one or two
seconds observe `baseline`, `new-key-published`, `cds-old-and-new`,
`parent-double-ds`, `new-key-active`, `cds-new-only`, `old-ds-withdrawn`, and
`complete`. These are legitimate low-risk overlap/withdrawal states. Unbound
must return `AD=true` and `192.0.2.10` at every significant phase.

## Diagnostics

Windows does not need a local `dig`; use the root container:

```powershell
docker compose -f lab/docker-compose.yml exec -T root dig '@172.30.0.12' victim.test. DNSKEY +dnssec
docker compose -f lab/docker-compose.yml exec -T root dig '@172.30.0.12' victim.test. CDS +dnssec
docker compose -f lab/docker-compose.yml exec -T root dig '@172.30.0.11' victim.test. DS +dnssec
docker compose -f lab/docker-compose.yml exec -T root dig '@172.30.0.14' www.victim.test. A +dnssec
docker compose -f lab/docker-compose.yml run --rm cds-sync verify-tampered
docker compose -f lab/docker-compose.yml logs --tail 100 provider tld unbound
```

`verify-tampered` alters an in-memory CDS digest and expects signature validation
to fail before update construction. It does not publish the altered data.

## Recovery and limitations

If a run is interrupted, do not delete volumes or keys. Safely finish the
recorded transition and return to a stable single-key state:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\reset-cds-rollover.ps1
```

If the parent is intentionally in attacker mode, restore the legitimate
delegation first, then run recovery:

```powershell
docker compose -f lab/docker-compose.yml run --rm registrar restore
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\reset-cds-rollover.ps1
```

Common failures are an inactive service, an attacker delegation, a missing root
anchor, expired signatures after a host-clock jump, or an interrupted KASP
transition. Inspect the logs and run recovery; never use `docker compose down -v`.

BIND 9.18's CSK policy normally swaps predecessor CDS for successor CDS at one
KASP event. For this compressed lab, the existing controller temporarily keeps
the predecessor goal and DS state `omnipresent`, so BIND itself publishes and
signs the observable old+new CDS overlap. After the new parent DS is
acknowledged, the controller returns the predecessor to `hidden`/`unretentive`.
The same controller's established safety checks then retire it. The short TTLs
and backdated acknowledgements are deterministic lab time compression, not
production rollover timing guidance.
