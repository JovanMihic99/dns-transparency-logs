# LoKey private DNSSEC lab

This directory contains LoKey's private DNS hierarchy. It runs entirely inside
an internal Docker bridge and does not publish DNS ports to Windows or change
Windows DNS settings.

The validated path is:

`Unbound -> private root (.) -> test. -> victim.test. provider`

The attacker remains separate and serves an independently signed synthetic copy
of `victim.test.`. The mock-registrar scenario can deliberately switch the
parent NS and DS records between the provider and attacker. Automatic rollover
scenarios are not implemented yet.

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

