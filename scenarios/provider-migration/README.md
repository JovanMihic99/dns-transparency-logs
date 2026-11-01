# Scenario 5: legitimate provider migration

This scenario moves `victim.test.` from the original provider at
`172.30.0.12` to an independent legitimate provider at `172.30.0.16`. Both
providers return `www.victim.test. A 192.0.2.10`, but the new provider has its
own persistent BIND signing volume and independent DNSSEC identity.

The scenario uses the existing `lab` Compose project and internal `dns_lab`
network. It does not reuse the attacker, replace the original provider, or
publish ports to the host.

## Trust-preserving state machine

Only four live states are accepted:

1. `ns.victim.test.` with OLD DS only.
2. `ns.victim.test.` with exactly OLD+NEW DS.
3. `ns.newprovider.test.` with exactly OLD+NEW DS.
4. `ns.newprovider.test.` with NEW DS only.

Any other NS or DS combination stops without an update. Saved metadata binds
the run to the exact old and new DNSKEY and DS RDATA, so a key-tag collision or
unrelated key change cannot be mistaken for a resumable migration.

The forward sequence is:

1. Validate both authoritative zones, their DNSKEY and ordinary-data RRSIGs,
   parent state, glue, and Unbound `AD=true`.
2. Atomically add `ns.newprovider.test. A 172.30.0.16` and NEW DS. OLD DS and
   OLD NS remain active.
3. Hold the Double-DS state for the measured DS/DNSKEY/glue TTL plus a
   propagation margin.
4. Install an exact collector pre-announcement for NEW NS and the OLD+NEW DS
   set. The controller requires two distinct collector snapshots after the
   file is installed.
5. Replace OLD NS with NEW NS while both DS records remain.
6. Hold that state for the maximum NS, glue, and negative-cache TTL plus a
   propagation margin.
7. Remove OLD DS, retain NEW DS, and complete another DS safety hold.

There is deliberately no dual-NS interval. Resolvers with cached OLD NS can
validate through OLD DS, while resolvers using NEW NS validate through NEW DS.
The Double-DS bridge remains until the OLD NS cache-safety interval has passed.

## Collector observation

The controller inherits the running `lokey-collector` container's `/app/data`
mount. The collector reads `/app/data/preannouncements.json` every poll. The
scenario merges one exact, expiring `victim.test` entry into that runtime file;
it refuses to overwrite another announcement. Before switching NS it requires:

- a collector snapshot of state 2 before installation; and
- two later, distinct snapshots while the exact announcement remains present.

Expected events are:

- `DS_ADDED`: low risk;
- `NS_CHANGED` plus `DNSKEY_CHANGED`: low risk because it matches the exact
  unexpired pre-announcement;
- `DS_REMOVED`: low risk because NEW DS still matches the current DNSKEY.

The scenario removes only its own exact announcement after completion or safe
reset. It does not clear collector history or logs.

## Commands (Windows PowerShell)

Run these from the repository root. The collector must already be running and
the shared lab must be in state 1 before any mutating command is used.

```powershell
$compose = @(
  '-f', '.\lab\docker-compose.yml',
  '-f', '.\scenarios\provider-migration\docker-compose.yml',
  '--profile', 'tools'
)

docker compose @compose build provider-migration
docker compose @compose up -d --no-deps --force-recreate tld
docker compose @compose up -d new-provider
docker compose @compose run --rm --no-deps provider-migration status
```

Run the complete migration:

```powershell
docker compose @compose run --rm --no-deps provider-migration run
```

Or expose each observable phase separately:

```powershell
docker compose @compose run --rm --no-deps provider-migration begin
docker compose @compose run --rm --no-deps provider-migration announce
docker compose @compose run --rm --no-deps provider-migration switch
docker compose @compose run --rm --no-deps provider-migration retire-old-ds
```

Resume only a recognized state with matching saved identities:

```powershell
docker compose @compose run --rm --no-deps provider-migration resume
```

Run the automated baseline → migration → safe reverse-reset test:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\test-provider-migration.ps1
```

## Safe reset and interruption recovery

Never delete the old or new provider volumes. Use:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\lab\reset-provider-migration.ps1
```

Reset reverses the migration safely: add OLD DS beside NEW, wait, publish and
prove an exact reverse pre-announcement, switch NS back while both DS records
remain, wait for NS/glue caches, then remove NEW DS and new-provider glue. An
ambiguous live state, missing metadata, changed key,
unexpected glue, expired/mismatched pre-announcement, failed RRSIG validation,
or failed Unbound AD check stops the process without guessing.

## Timing limitations

This isolated lab uses approximately 30-second DNS TTLs and a five-second
propagation margin. `LOKEY_MIGRATION_OBSERVATION_SECONDS` can lengthen visible
phases but cannot shorten TTL-derived holds. These compressed timings are for
the hackathon lab only and are not production migration guidance.
