LoKey

Certificate Transparency for DNSSEC. LoKey records every DNSSEC key change in a tamper-evident log and tells a normal key rollover apart from a registrar hijack.

Built by team Gilipteri for the DNS SEC(urity) Hackathon.

The idea in 30 seconds
A registrar hijack swaps a domain’s NS and DS records in one step.
DNSSEC still says “secure”, because the attacker signs with their own key.
A real key rollover leaves a trail: the new key shows up signed by the old key first.
LoKey checks for that trail. No trail means a high-risk alert.
Safety rules (read first)
Attacks run only in the isolated Docker lab, on .test domains, with synthetic data.
Alerts go only to our own team channel, never to real domain owners.
If something real looks like a hijack: stop, publish nothing, tell the organisers privately.
Never run docker compose down --volumes (or -v) in lab/. It deletes the lab’s DNSSEC keys. Plain docker compose down is fine.
What you need
Docker with Compose v2 (tested on Ubuntu 24.04).
Your user in the docker group, or put sudo before every docker command.
Internet access only to build the images. Running the lab needs none.
For the unit tests only: Python 3.12 and a venv.
Quick start

Run everything from the repository root. Keep this order: the collector joins networks that the lab and the log create.

1. Start the lab
bash
cd lab
docker compose up -d
docker compose build registrar
docker compose run --rm --no-deps registrar status
cd ..

Works when: status prints delegation: provider and ad=true. (docker compose ps -a should show everything healthy and dnssec-setup as Exited (0).)

More checks and manual dig inspection: lab/README.md.

2. Start the log and dashboard
bash
touch logs/.env
cd logs && docker compose up -d --build && cd ..
curl -s http://127.0.0.1:5000/health

Works when: you get {"service":"lokey-log","status":"ok"}.

logs/.env must exist (it can be empty), or Compose refuses to start.

3. Start the collector
bash
mkdir -p collector/data
cd collector && docker compose up -d --build
docker compose logs -f

Works when: you see [baseline] victim.test ns=['ns.victim.test.'] .... Press Ctrl+C to stop watching, then cd ...

Create collector/data yourself first. Otherwise Docker creates it as root and the container (UID 1000) can’t write to it. If your user isn’t UID 1000, set LOKEY_UID and LOKEY_GID when you build and start the log and collector.

4. Open the dashboard

http://127.0.0.1:5000

Run the demo

Always add --no-deps to registrar commands (see Troubleshooting).

Registrar hijack (scenario 6): should alert
bash
cd lab
docker compose run --rm --no-deps registrar hijack

Expected: within about 10 seconds the collector logs a high-risk event and [log] 201, and the event appears on the dashboard.

Undo it:

bash
docker compose run --rm --no-deps registrar restore
cd ..

The restore also scores high. That’s expected: the old key comes back with no fresh trail. To make it score low, pre-announce it (below).

Double-KSK rollover (scenario 2): should stay quiet

Wait about 25 seconds between commands, so each step lands in its own collector poll. Every step should score low.

bash
cd lab
docker compose run --rm ksk-rollover begin
docker compose run --rm --no-deps registrar sync-provider-ds
docker compose run --rm ksk-rollover acknowledge-published
NEW_TAG=$(docker compose run --rm -T ksk-rollover new-tag)
docker compose run --rm --no-deps registrar sync-provider-ds --key-tag "$NEW_TAG"
docker compose run --rm ksk-rollover acknowledge-withdrawn
docker compose run --rm ksk-rollover events
cd ..

More detail: “Scenario 2” in lab/README.md.

Make a planned change score low (pre-announcement)

Write collector/data/preannouncements.json before the change and delete it afterwards. The collector rereads it every poll.

json
[{"domain": "victim.test", "new_ns": ["ns.victim.test."], "new_ds": ["<DS text>"], "valid_until": "2026-11-01T23:59:59Z"}]

new_ds is optional. A change whose new NS (and DS, if given) match an unexpired entry scores low.

Reset before a demo

Clears events and history but keeps the lab keys and the log’s signing key.

bash
cd lab && docker compose run --rm --no-deps registrar restore && cd ..
cd collector && docker compose stop && cd ..
cd logs && docker compose stop && cd ..
mkdir -p ~/lokey-old
mv collector/data/* ~/lokey-old/
mv logs/data/events.jsonl logs/data/assessments.jsonl logs/data/tree_heads.jsonl ~/lokey-old/
cd logs && docker compose up -d && cd ..
cd collector && docker compose up -d && cd ..
Keep the .pem files in logs/data/.
git status will show some logs/data/ files as deleted. Don’t commit that.
Moving collector/data/state.json resets the baseline and the quarantine history.
To recover an interrupted rollover, use the reset scripts in the scenario READMEs.
Troubleshooting
Problem	Fix
env file … not found when starting the log	touch logs/.env (it can be empty)
dependency failed to start on a registrar command	Add --no-deps. Unbound is briefly unhealthy after every hijack.
Collector can’t write to collector/data	Create the folder as your own user before starting; check LOKEY_UID/LOKEY_GID
Provider unhealthy after upgrading an existing lab to the lokey-rollover policy	Stop the provider, delete only db.victim.test.signed and its .jnl from the lab_provider_state volume. Keep keys/.
acknowledge-withdrawn fails with Missing successor signature … TYPE65534	BIND is still re-signing; it finishes the rollover on its own schedule
Double-DS, CDS rollover or lab reset scripts don’t run	They’re PowerShell only (lab/*.ps1)
Known limitations
Glue-only change not detected: an attacker who keeps ns.victim.test. and only changes its glue address is not caught.
Quarantine is permanent: after a legitimate but unannounced migration (high), the new keys stay quarantined until the domain’s state is reset. Pre-announce migrations.
GET /tree-head stores a new head on every call, so the history fills up with heads of the same size.
verify.py only checks tree-head signatures, not inclusion or consistency proofs yet.
logs/README.md shows an old event format (flat change/risk keys). The log only accepts the format in the reference below.
No one-command demo yet: demo/run.sh doesn’t exist.
Scenarios 5a, 7 and 8 are on unmerged feature branches.
Scenario status

“Unit” means covered by tests/test_scoring.py with real ECDSA signatures built in memory.

#	Scenario	Expected	Status
1	ZSK-only rollover	low	Lab script (PowerShell), unit. See scenarios/zsk-rollover/README.md
2	Double-KSK rollover	low at every step	Live on Linux, unit. See above
3	Double-DS rollover	low	Lab script (PowerShell only), unit. See scenarios/double-ds-rollover/README.md
4	CDS-driven rollover	low	cds-sync service + PowerShell driver, unit. See scenarios/cds-rollover/README.md
5a	Provider migration, not announced	high	Unit only (branch feature/provider-migration)
5b	Provider migration, pre-announced	low (high once expired)	Unit
6	Registrar hijack	high	Live on Linux, unit. See above
7	Parent DS removal	high	Unit only (branch feature/ds-removal)
8	NS change on an unsigned domain	medium	Unit only (branch feature/unsigned-ns-change)
How it works
collector  ->  scoring  ->  log (Merkle tree)  ->  dashboard + alerts
Collect. Every 10 s the collector reads DS from the .test server, NS and glue from its referral, and DNSKEY and CDS from the domain’s own name server (never a cache). It compares with the last snapshot. The first poll is a baseline and emits nothing; a failed query skips that poll instead of reporting records as removed.
Score. Each change gets low, medium or high plus reasons, based on key continuity (scoring/rules.py).
Log. The event is POSTed to the log, which appends the observation as a Merkle leaf and serves signed tree heads and proofs. The collector also keeps a local backup and a state file.
Alert. The dashboard shows every event. Telegram alerts for high-risk events can be switched on (see Configuration).

Three Compose projects run side by side. The lab network is internal, so the lab DNS servers have no internet route.

lab (project "lab", network lab_dns_lab, internal)          log (project "logs", network logs_default)
  root 172.30.0.10 · tld 172.30.0.11 · provider 172.30.0.12      lokey (Flask/gunicorn :5000, published on the host)
  attacker 172.30.0.13 · unbound 172.30.0.14                       data in logs/data (bind mount)
                \                                              /
                 collector (project "collector", container lokey-collector)
                 polls tld 172.30.0.11 every 10 s, POSTs to http://lokey:5000/events
                 data in collector/data (bind mount)
Component	Address	Notes
tld (.test)	172.30.0.11	Re-signs after TSIG dynamic updates from the mock registrar
provider	172.30.0.12	Serves victim.test as ns.victim.test. (in-zone, glue); policy lokey-rollover, one CSK
attacker	172.30.0.13	Serves its own signed copy of victim.test as ns.attacker.test.
unbound	172.30.0.14	Validating resolver, trust anchor = the lab root
log API and dashboard	http://127.0.0.1:5000 (host), http://lokey:5000 (inside logs_default)	
Reference
Event format

Each event is {"observation": …, "assessment": …}; the log accepts exactly these two keys. Only the observation is hashed into the Merkle tree, as SHA-256(0x00 || canonical_observation). The assessment is stored separately (linked by leaf_hash), so scoring rules can change without touching the log.

Canonical form: json.dumps(observation, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

json
{"observation": {"domain": "victim.test", "observed_at": "2026-10-31T19:38:33Z",
                 "changes": ["NS_CHANGED", "DS_REPLACED", "DNSKEY_CHANGED"],
                 "before": {"ns": ["ns.victim.test."], "ds": ["43753 13 2 e5fc…"], "dnskey": ["257 3 13 h6PJ…"], "cds": []},
                 "after":  {"ns": ["ns.attacker.test."], "ds": ["16134 13 2 29bf…"], "dnskey": ["257 3 13 ++wP…"], "cds": []}},
 "assessment": {"risk": "high", "rules_version": "v1.1",
                "reasons": ["NS changed at the same time, not pre-announced",
                            "DS replaced with no trail signed by the previously trusted key"]}}
Change type	Meaning
NS_CHANGED	The NS set at the parent changed
DS_ADDED	New DS added, all old DS still there
DS_REMOVED	Some DS removed, at least one remains
DS_ALL_REMOVED	Every DS removed
DS_REPLACED	DS added and removed in the same poll
DNSKEY_CHANGED	The DNSKEY set changed (also reported alongside a DS change)
CDS_PUBLISHED	New CDS record(s) appeared
CDS_REMOVED	CDS record(s) disappeared; a swap reports both CDS types
Scoring rules v1.1
Trusted key: a DNSKEY that matches a parent DS and whose DNSKEY set validates with it.
Trail: the new key published in a DNSKEY set signed by a previously trusted key, or a CDS signed by one, seen at least one poll before the DS change.
The event’s risk is the highest of its findings.
Quarantine: a key that first becomes trusted in a high-risk change never counts as a trail or a clean signer until the domain’s state is reset.
If scoring itself crashes, the event is still sent with risk: high and the error as the reason.
Situation	Risk
NS change matching an active pre-announcement	low
DS replaced, the new key has a trail	low
New DS added, old DS stays	low
Old DS removed, a remaining DS matches a current key	low
All DS removed after a signed CDS delete request	low
DNSKEY set changed, still signed by a clean trusted key	low
CDS published and signed by a trusted key; CDS removed	low
NS change on a signed domain without DS change; NS change on an unsigned domain	medium
DS removed and no remaining DS matches a current key	medium
DNSKEY change signed only by a quarantined key, or no longer validating	medium
CDS published but not signed by a trusted key	medium
DS replaced or all removed with no trail; any DS change together with an unannounced NS change	high
Log API

Endpoints are in logs/app.py.

Method	Path	Purpose
GET	/	Web dashboard
GET	/api/dashboard	Dashboard data: events joined with assessments, stats, latest tree head
GET	/api/tree-heads	Stored tree heads, newest first, with signature check
GET	/health	Health check
GET	/events	Stored observations
GET	/assessments	Stored assessments
POST	/events	Append one event (observation + assessment)
GET	/tree-head	Signs and stores a new tree head on every call
GET	/proof/<index>	Inclusion proof (audit path and root) for leaf index
GET	/consistency/<old_size>	Consistency proof from an older tree size to the current one

Check the stored tree-head signatures against the log’s public key:

bash
cd logs && docker compose exec lokey python verify.py && cd ..

Hashing scheme: logs/docs.md.

Configuration

Collector settings come from LOKEY_* variables in collector/docker-compose.yml, or the matching flags of python -m collector.run --help:

Variable	Flag	Compose value
LOKEY_TLD_IP	--tld	172.30.0.11
LOKEY_LOG_URL	--log-url	http://lokey:5000/events
LOKEY_EVENTS	--out	/app/data/events.jsonl
LOKEY_STATE	--state	/app/data/state.json
LOKEY_PREANNOUNCEMENTS	--preannouncements	/app/data/preannouncements.json

The polling interval is --interval (default 10 s). Domains to watch are the positional arguments (victim.test in Compose).

Telegram alerts (high risk only) are read from logs/.env. This file holds secrets, is ignored by Git and must never be committed. Point alerts only at the team’s own chat.

Variable	Meaning
TELEGRAM_ENABLED	true to enable
TELEGRAM_BOT_TOKEN	Bot token
TELEGRAM_CHAT_ID	Team chat ID
LOKEY_PUBLIC_URL	Optional base URL for the proof link

Data folders (never commit their contents):

logs/data/ (LOKEY_DATA_DIR, relative to the working directory): events.jsonl (the Merkle leaves), assessments.jsonl, tree_heads.jsonl, log_ed25519_private.pem, log_ed25519_public.pem.
collector/data/: events.jsonl (local backup), state.json (last snapshot and scoring history per domain; a restart resumes instead of re-baselining), optional preannouncements.json.
Tests
Suite	Command	Needs	Expected
Collector and scoring	python -m pytest -q tests/ (repo root)	venv with dnspython[dnssec], pytest	19 passed
Log	cd logs && python -m pytest -q tests/ (must run from logs/)	Flask, cryptography, pytest	11 passed
Live scenarios	TODO (unverified): tests/live_scenarios.sh is not in the repository yet	lab, log and collector running	5 passed, 0 failed

One venv for both unit suites:

bash
python3 -m venv .venv && . .venv/bin/activate
pip install "dnspython[dnssec]" pytest Flask requests
python -m pytest -q tests/
cd logs && python -m pytest -q tests/ && cd ..

Don’t install logs/requirements.txt into the same venv: it pins cryptography==45.0.7, which conflicts with dnspython[dnssec].

Without containers. With the lab running, start the log with cd logs && python app.py, then run the collector from the repo root:

bash
python -m collector.run victim.test --log-url http://127.0.0.1:5000/events

TODO (unverified): the host reaching the internal lab network at 172.30.0.11 was reported working on Linux but not checked for this README.