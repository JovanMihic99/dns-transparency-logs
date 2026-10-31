# LoKey private DNSSEC lab

This directory contains LoKey's private DNS hierarchy. It runs entirely inside
an internal Docker bridge and does not publish DNS ports to Windows or change
Windows DNS settings.

The validated path is:

`Unbound -> private root (.) -> test. -> victim.test. provider`

The attacker remains separate and serves an independently signed synthetic copy
of `victim.test.`. The mock-registrar scenario can deliberately switch the
parent NS and DS records between the provider and attacker. The lab also has
legitimate direct-registrar and CDS-driven KSK rollover scenarios.

## What persists

Docker named volumes store each signed authority's DNSSEC keys, journal, and
signed-zone state. A separate volume stores Unbound's public private-root trust
anchor. `docker compose stop`, `start`, `restart`, and ordinary `down`/`up`
cycles preserve these identities.

Never run `docker compose down --volumes` unless you intentionally want to
destroy all lab DNSSEC identities and have explicit permission to do so.

## Start the lab

Open Windows PowerShell in this directory:

```powershell
Set-Location C:\path\to\dns-transparency-logs\lab
docker compose config
docker compose up -d
docker compose ps -a
```

On the first start, BIND creates independent keys for `.`, `test.`, and
`victim.test.`. The one-shot `dnssec-setup` service derives and installs the two
child DS records, writes the private root's public KSK/CSK DNSKEY for Unbound,
and records that initialization is complete. This marker prevents restarts from
overwriting later registrar exercises.

`dnssec-setup` should show `Exited (0)`. That is success, not a crashed server.

## Run the automated positive checks

The BIND image already contains `dig`, `dnssec-dsfromkey`, and the other DNS
tools used by the tests. Windows does not need its own copy of `dig`.

```powershell
docker compose exec root sh /opt/lab/test-dnssec.sh
```

The script exits nonzero if any DNSKEY, RRSIG, DS match, trust-anchor match,
validated address, or AD-flag check fails.

## Inspect the chain manually

PowerShell requires the quoted `@server` arguments shown below.

```powershell
docker compose exec root dig '@172.30.0.10' . DNSKEY +dnssec
docker compose exec root dig '@172.30.0.10' test. DS +dnssec
docker compose exec root dig '@172.30.0.11' test. DNSKEY +dnssec
docker compose exec root dig '@172.30.0.11' victim.test. DS +dnssec
docker compose exec root dig '@172.30.0.12' victim.test. DNSKEY +dnssec
docker compose exec root dig '@172.30.0.14' www.victim.test. A +dnssec
```

The final Unbound response must contain `status: NOERROR`, `192.0.2.10`, and
the `ad` flag. The AD flag proves that Unbound validated the complete chain;
merely seeing an RRSIG is not sufficient.

## Controlled validation-failure test

This test temporarily replaces the `victim.test.` DS with an incorrect digest,
expects Unbound to return `SERVFAIL` without AD, and restores the correct DS in
a PowerShell `finally` block. Do not interrupt it while it is restoring state.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-dnssec-negative.ps1
```

After restoration, the script reruns every positive check.

## Prove key identity survives a restart

Record the root DS, restart without deleting volumes, and compare it afterward:

```powershell
$Before = docker compose exec root sh -c "dig '@127.0.0.1' . DNSKEY +noall +answer | dnssec-dsfromkey -2 -f - ."
docker compose stop
docker compose up -d
$After = docker compose exec root sh -c "dig '@127.0.0.1' . DNSKEY +noall +answer | dnssec-dsfromkey -2 -f - ."
$Before
$After
$Before -eq $After
docker compose exec root sh /opt/lab/test-dnssec.sh
```

The comparison should print `True`.

## Mock-registrar preparation

The `test.` authority accepts TSIG-authenticated dynamic updates only for the
`victim.test.` NS and DS record types. BIND journals and automatically re-signs
accepted changes. The lab key is intentionally local and synthetic; it must
never be used for real DNS infrastructure.

## Stop, start, and inspect

```powershell
docker compose stop
docker compose start
docker compose restart
docker compose logs --tail 100
docker compose logs dnssec-setup
```

Remove containers and the internal network while preserving keys:

```powershell
docker compose down
```

## Configuration and troubleshooting

```powershell
docker compose exec root named-checkconf /etc/bind/named.conf
docker compose exec tld named-checkconf /etc/bind/named.conf
docker compose exec provider named-checkconf /etc/bind/named.conf
docker compose exec attacker named-checkconf /etc/bind/named.conf
docker compose exec unbound unbound-checkconf /opt/unbound/etc/unbound/unbound.conf
docker compose ps -a
docker compose logs --tail 200 root tld provider unbound dnssec-setup
```

If Unbound returns `SERVFAIL`, inspect the DS records, DNSKEYs, system time, and
logs. DNSSEC signatures are time-sensitive. Ordinary zone TTLs remain 30
seconds, while BIND's supported default DNSSEC policy intentionally uses its own
safer DNSKEY, signature, publication, and rollover timing values.

Unbound has only the simulated root hints and the generated public DNSKEY for
the private root. No real root hints, public trust anchor, forwarding server, or
fallback resolver is configured.

## Mock registrar and signed hijack demonstration

The mock registrar is a Python/dnspython CLI under `../scenarios/registrar`.
It derives DS records from live child DNSKEYs and sends narrowly authorized,
TSIG-signed updates to the `test.` authority. It never contacts real DNS.

Build the registrar image once after downloading the pinned base image and
Python dependency:

```powershell
docker compose build registrar
```

Show the current delegation, signed-DS match, and recursive result:

```powershell
docker compose run --rm registrar status
```

Switch the parent delegation and DS to the independently signed attacker, then
restart Unbound as a controlled cache flush:

```powershell
docker compose run --rm registrar hijack
docker compose restart unbound
docker compose exec root dig '@172.30.0.14' www.victim.test. A +dnssec
docker compose run --rm registrar status
```

The answer must be `192.0.2.66` and include the AD flag. AD is expected because
the parent now publishes the attacker's valid DS; this is an authorized but
malicious registrar change, not a DNSSEC cryptographic failure.

Restore the legitimate provider and flush the resolver cache again:

```powershell
docker compose run --rm registrar restore
docker compose restart unbound
docker compose exec root dig '@172.30.0.14' www.victim.test. A +dnssec
docker compose run --rm registrar status
```

The restored answer must be `192.0.2.10` with AD.

Run the complete baseline -> hijack -> restore regression, including unsigned
UPDATE rejection, attacker signing/key persistence, DS matching, and AD checks:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-registrar-hijack.ps1
```

The regression restores the provider in a `finally` block even when a check
fails. Do not interrupt it while the restoration message is displayed.

## Scenario 2: legitimate Double-KSK rollover

The provider uses the explicit `lokey-rollover` DNSSEC policy. It keeps BIND's
existing ECDSAP256SHA256 combined signing key (CSK) architecture: every CSK is
also a KSK because it has the SEP/KSK flag. BIND implements its KSK-side
transition using the normal Double-KSK sequence.

The policy uses short lab-only TTL and propagation margins. The scenario also
uses BIND's `dnssec-settime -s` test facility to compress waiting time, but only
after proving that every live authoritative RRset is signed by the successor.
This clock compression is suitable for this isolated synthetic lab, not a real
production zone.

Run the complete regression from PowerShell:

```powershell
Set-Location C:\path\to\dns-transparency-logs\lab
docker compose up -d
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-ksk-rollover.ps1
```

The test does not restart the lab between rollover phases. It flushes only the
`victim.test.` Unbound cache so each AD assertion performs fresh validation.
The final line reports the predecessor and successor key tags.

To inspect the current BIND policy state and all JSONL observations:

```powershell
docker compose run --rm ksk-rollover status
docker compose run --rm ksk-rollover events
```

Each new run has a `run_id`. The important low-risk sequence is:

1. `baseline`: one DNSKEY and its matching parent DS, AD=true.
2. `new-key-published`: old parent DS, two DNSKEYs, both DNSKEY signatures,
   AD=true. This proves the trusted predecessor authenticated the successor.
3. `parent-double-ds`: old and new DS records coexist, AD=true.
4. `new-key-active`: successor DS has been acknowledged to BIND, AD=true.
5. `old-ds-withdrawn`: parent contains only the successor DS while both child
   DNSKEYs still overlap, AD=true.
6. `complete`: only the successor DNSKEY and DS remain, AD=true.

For a manual, observable transition:

```powershell
docker compose up -d
docker compose kill -s HUP unbound
powershell -NoProfile -ExecutionPolicy Bypass -File .\reset-ksk-rollover.ps1
docker compose run --rm ksk-rollover begin
docker compose exec unbound unbound-control flush_zone victim.test.
docker compose exec root dig '@172.30.0.14' www.victim.test. A +dnssec

docker compose run --rm registrar sync-provider-ds
docker compose exec unbound unbound-control flush_zone victim.test.
docker compose run --rm ksk-rollover acknowledge-published

$NewTag = docker compose run --rm ksk-rollover new-tag
docker compose run --rm registrar sync-provider-ds --key-tag $NewTag
docker compose exec unbound unbound-control flush_zone victim.test.
docker compose run --rm ksk-rollover acknowledge-withdrawn

docker compose exec unbound unbound-control flush_zone victim.test.
docker compose exec root dig '@172.30.0.14' www.victim.test. A +dnssec
docker compose run --rm ksk-rollover events
```

If a manual run is interrupted, this command safely completes it at the
successor key; it does not delete keys or volumes and does not attempt to return
to a cryptographically retired predecessor:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\reset-ksk-rollover.ps1
```

# Scenario 4: CDS-driven rollover

Scenario 4 validates child CDS cryptographically before changing the parent DS,
maintains an observable double-DS overlap, and preserves `AD=true` throughout.
See [`scenarios/cds-rollover/README.md`](../scenarios/cds-rollover/README.md) for
the architecture, PowerShell demonstration, diagnostics, and safe recovery.

Run the complete test from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-cds-rollover.ps1
```

## Scenario 1: legitimate ZSK-only rollover

Scenario 1 temporarily replaces only the provider container with an isolated
split KSK/ZSK signing environment. It retains the parent-trusted CSK public and
private key as the KSK, generates independent ZSKs, and leaves the shared
`provider_state` volume untouched. Parent DS and NS records do not change.

Run the complete Scenario 1 test from the repository root:

```powershell
docker compose -p lab -f .\lab\docker-compose.yml up -d
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-zsk-rollover.ps1
```

The test checks old/new ZSK publication and signature overlap, exact KSK
identity, unchanged parent DS/NS, measured TTL cache safety, and Unbound
`AD=true` at every phase. It restores the original CSK provider even when a
test fails. For safe manual recovery:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\reset-zsk-rollover.ps1
```

Do not remove either provider volume. See
[`scenarios/zsk-rollover/README.md`](../scenarios/zsk-rollover/README.md) for
the architecture, phase commands, observation output, and rollback reasoning.

## Scenario 3: legitimate Double-DS KSK rollover

Scenario 3 uses the existing CSK rollover and TSIG registrar infrastructure,
but independently proves an observable parent DS overlap: OLD only, exactly
OLD+NEW, then NEW only. It derives exact DS RDATA from an authenticated child
DNSKEY response and requires fresh Unbound `AD=true` validation throughout.

Run the complete PowerShell test from the repository root:

```powershell
docker compose -f .\lab\docker-compose.yml up -d
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-double-ds-rollover.ps1 -ObservationDurationSeconds 5
```

For conservative recovery after interruption:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\reset-double-ds-rollover.ps1 -ObservationDurationSeconds 5
```

Recovery completes toward the authenticated successor; it never deletes
volumes, forces ambiguous state, or restores a retired predecessor. See
[`scenarios/double-ds-rollover/README.md`](../scenarios/double-ds-rollover/README.md)
for phases, safety checks, diagnostics, and timing limitations.

