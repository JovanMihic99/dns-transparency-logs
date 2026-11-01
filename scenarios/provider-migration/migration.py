#!/usr/bin/env python3
"""State-driven legitimate provider migration for the isolated LoKey lab."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update


TLD = "172.30.0.11"
OLD_PROVIDER = "172.30.0.12"
NEW_PROVIDER = "172.30.0.16"
UNBOUND = "172.30.0.14"
ZONE = dns.name.from_text("victim.test.")
TLD_ZONE = dns.name.from_text("test.")
OLD_NS = "ns.victim.test."
NEW_NS = "ns.newprovider.test."
OLD_GLUE = "172.30.0.12"
NEW_GLUE = "172.30.0.16"
EXPECTED_ADDRESS = "192.0.2.10"
TTL = 30
PROPAGATION_MARGIN = 5
TSIG_NAME = "mock-registrar."
STATE_NAMES = {
    1: "OLD NS / OLD DS",
    2: "OLD NS / OLD+NEW DS",
    3: "NEW NS / OLD+NEW DS",
    4: "NEW NS / NEW DS",
}


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Identity:
    server: str
    dnskey_text: str
    ds_text: str
    key_tag: int
    dnskey_ttl: int
    a_ttl: int


@dataclass(frozen=True)
class LiveState:
    number: int
    nameservers: tuple[str, ...]
    parent_ds: tuple[str, ...]
    ns_ttl: int
    ds_ttl: int
    negative_ttl: int


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def state_path() -> Path:
    return Path(os.environ.get("MIGRATION_STATE_FILE", "/state/current.json"))


def preannouncements_path() -> Path:
    return Path(os.environ.get("PREANNOUNCEMENTS_FILE", "/app/data/preannouncements.json"))


def collector_state_path() -> Path:
    return Path(os.environ.get("COLLECTOR_STATE_FILE", "/app/data/state.json"))


def normalize_ds(text: str) -> str:
    return " ".join(text.split()).upper()


def query(server: str, owner: dns.name.Name | str, rdtype: dns.rdatatype.RdataType) -> dns.message.Message:
    request = dns.message.make_query(owner, rdtype, want_dnssec=True)
    request.flags &= ~dns.flags.RD
    try:
        response, _ = dns.query.udp_with_fallback(request, server, timeout=4)
    except dns.exception.DNSException as exc:
        raise MigrationError(f"query {owner} {dns.rdatatype.to_text(rdtype)} @{server} failed: {exc}") from exc
    if response.rcode() != dns.rcode.NOERROR:
        raise MigrationError(
            f"query {owner} {dns.rdatatype.to_text(rdtype)} @{server} returned "
            f"{dns.rcode.to_text(response.rcode())}"
        )
    return response


def find_rrset(
    response: dns.message.Message,
    owner: dns.name.Name | str,
    rdtype: dns.rdatatype.RdataType,
    covers: dns.rdatatype.RdataType = dns.rdatatype.NONE,
):
    wanted = dns.name.from_text(str(owner))
    for section in (response.answer, response.authority, response.additional):
        for rrset in section:
            if rrset.name == wanted and rrset.rdtype == rdtype and rrset.covers == covers:
                return rrset
    return None


def require_rrset(response, owner, rdtype, covers=dns.rdatatype.NONE):
    rrset = find_rrset(response, owner, rdtype, covers)
    if rrset is None:
        covered = f" covering {dns.rdatatype.to_text(covers)}" if covers else ""
        raise MigrationError(f"missing {dns.rdatatype.to_text(rdtype)}{covered} for {owner}")
    return rrset


def validate_rrset(rrset, signatures, keys, key_name: dns.name.Name) -> None:
    try:
        dns.dnssec.validate(rrset, signatures, {key_name: keys})
    except (dns.exception.DNSException, ValueError) as exc:
        raise MigrationError(f"DNSSEC validation failed for {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}: {exc}") from exc


def read_identity(server: str) -> Identity:
    key_response = query(server, ZONE, dns.rdatatype.DNSKEY)
    keys = require_rrset(key_response, ZONE, dns.rdatatype.DNSKEY)
    key_signatures = require_rrset(key_response, ZONE, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)
    validate_rrset(keys, key_signatures, keys, ZONE)
    eligible = [key for key in keys if (key.flags & 0x0101) == 0x0101]
    if len(eligible) != 1 or len(keys) != 1:
        raise MigrationError(
            f"{server} must expose exactly one stable eligible CSK; found {len(keys)} DNSKEY(s), "
            f"{len(eligible)} eligible"
        )
    key = eligible[0]
    ds = dns.dnssec.make_ds(ZONE, key, "SHA256")

    a_response = query(server, "www.victim.test.", dns.rdatatype.A)
    addresses = require_rrset(a_response, "www.victim.test.", dns.rdatatype.A)
    a_signatures = require_rrset(a_response, "www.victim.test.", dns.rdatatype.RRSIG, dns.rdatatype.A)
    validate_rrset(addresses, a_signatures, keys, ZONE)
    actual_addresses = sorted(record.address for record in addresses)
    if actual_addresses != [EXPECTED_ADDRESS]:
        raise MigrationError(f"{server} returned unexpected authoritative addresses: {actual_addresses}")
    return Identity(
        server=server,
        dnskey_text=" ".join(key.to_text().split()),
        ds_text=normalize_ds(ds.to_text()),
        key_tag=dns.dnssec.key_id(key),
        dnskey_ttl=keys.ttl,
        a_ttl=addresses.ttl,
    )


def tld_keys():
    response = query(TLD, TLD_ZONE, dns.rdatatype.DNSKEY)
    keys = require_rrset(response, TLD_ZONE, dns.rdatatype.DNSKEY)
    signatures = require_rrset(response, TLD_ZONE, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)
    validate_rrset(keys, signatures, keys, TLD_ZONE)
    return keys


def parent_records() -> tuple[tuple[str, ...], tuple[str, ...], int, int, int]:
    ns_response = query(TLD, ZONE, dns.rdatatype.NS)
    ns = require_rrset(ns_response, ZONE, dns.rdatatype.NS)
    nameservers = tuple(sorted(record.target.to_text().lower() for record in ns))

    ds_response = query(TLD, ZONE, dns.rdatatype.DS)
    ds = require_rrset(ds_response, ZONE, dns.rdatatype.DS)
    ds_signatures = require_rrset(ds_response, ZONE, dns.rdatatype.RRSIG, dns.rdatatype.DS)
    validate_rrset(ds, ds_signatures, tld_keys(), TLD_ZONE)
    ds_text = tuple(sorted(normalize_ds(record.to_text()) for record in ds))

    soa_response = query(TLD, TLD_ZONE, dns.rdatatype.SOA)
    soa = require_rrset(soa_response, TLD_ZONE, dns.rdatatype.SOA)
    negative_ttl = min(soa.ttl, min(record.minimum for record in soa))
    return nameservers, ds_text, ns.ttl, ds.ttl, negative_ttl


def glue(owner: str) -> tuple[tuple[str, ...], int]:
    request = dns.message.make_query(owner, dns.rdatatype.A, want_dnssec=True)
    request.flags &= ~dns.flags.RD
    try:
        response, _ = dns.query.udp_with_fallback(request, TLD, timeout=4)
    except dns.exception.DNSException as exc:
        raise MigrationError(f"query {owner} A @{TLD} failed: {exc}") from exc
    if response.rcode() == dns.rcode.NXDOMAIN:
        return (), 0
    if response.rcode() != dns.rcode.NOERROR:
        raise MigrationError(
            f"query {owner} A @{TLD} returned {dns.rcode.to_text(response.rcode())}"
        )
    rrset = find_rrset(response, owner, dns.rdatatype.A)
    if rrset is None:
        return (), 0
    return tuple(sorted(record.address for record in rrset)), rrset.ttl


def assert_unbound() -> None:
    request = dns.message.make_query("www.victim.test.", dns.rdatatype.A, want_dnssec=True)
    try:
        response = dns.query.udp(request, UNBOUND, timeout=5)
    except dns.exception.DNSException as exc:
        raise MigrationError(f"Unbound query failed: {exc}") from exc
    addresses = find_rrset(response, "www.victim.test.", dns.rdatatype.A)
    actual = sorted(record.address for record in addresses) if addresses else []
    if response.rcode() != dns.rcode.NOERROR or not response.flags & dns.flags.AD or actual != [EXPECTED_ADDRESS]:
        raise MigrationError(
            "Unbound invariant failed: "
            f"rcode={dns.rcode.to_text(response.rcode())} AD={bool(response.flags & dns.flags.AD)} A={actual}"
        )


def flush_unbound_zone() -> None:
    config = os.environ.get("UNBOUND_CONTROL_CONFIG", "/run/unbound-control.conf")
    result = subprocess.run(
        ["unbound-control", "-c", config, "flush_zone", "victim.test."],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise MigrationError(f"could not flush the synthetic victim.test. cache: {detail}")
    print("flushed only the synthetic victim.test. resolver cache after the NS cut")


def load_saved(required: bool = False) -> dict | None:
    path = state_path()
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError:
        if required:
            raise MigrationError("migration metadata is missing; refusing to infer a transitional state")
        return None
    except (OSError, ValueError) as exc:
        raise MigrationError(f"cannot read migration metadata {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise MigrationError("migration metadata is malformed")
    return value


def save_saved(value: dict) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def verify_saved_identities(saved: dict, old: Identity, new: Identity) -> None:
    expected = {
        "old_dnskey": old.dnskey_text,
        "old_ds": old.ds_text,
        "old_tag": old.key_tag,
        "new_dnskey": new.dnskey_text,
        "new_ds": new.ds_text,
        "new_tag": new.key_tag,
    }
    for field, value in expected.items():
        if saved.get(field) != value:
            raise MigrationError(f"saved {field} does not match the live DNSSEC identity")


def classify(old: Identity, new: Identity, saved: dict | None) -> LiveState:
    if old.key_tag == new.key_tag or old.dnskey_text == new.dnskey_text:
        raise MigrationError("old and new providers do not have independent DNSSEC identities")
    nameservers, parent_ds, ns_ttl, ds_ttl, negative_ttl = parent_records()
    old_only = (old.ds_text,)
    new_only = (new.ds_text,)
    both = tuple(sorted((old.ds_text, new.ds_text)))
    combinations = {
        ((OLD_NS,), old_only): 1,
        ((OLD_NS,), both): 2,
        ((NEW_NS,), both): 3,
        ((NEW_NS,), new_only): 4,
    }
    number = combinations.get((nameservers, parent_ds))
    if number is None:
        raise MigrationError(
            "unrecognized migration state; no mutation is safe: "
            f"NS={list(nameservers)} DS={list(parent_ds)}"
        )
    if number != 1 and saved is None:
        raise MigrationError(
            f"live DNS is transitional ({STATE_NAMES[number]}) but saved migration metadata is missing"
        )
    if saved is not None:
        verify_saved_identities(saved, old, new)

    old_glue, _ = glue(OLD_NS)
    new_glue, _ = glue(NEW_NS)
    expected_old_glue = (OLD_GLUE,) if number in (1, 2) else ()
    if old_glue != expected_old_glue:
        raise MigrationError(
            f"old-provider glue is not exact for {STATE_NAMES[number]}: {list(old_glue)}"
        )
    expected_new_glue = () if number == 1 else (NEW_GLUE,)
    if new_glue != expected_new_glue:
        raise MigrationError(
            f"new-provider glue is not exact for {STATE_NAMES[number]}: {list(new_glue)}"
        )
    assert_unbound()
    return LiveState(number, nameservers, parent_ds, ns_ttl, ds_ttl, negative_ttl)


def inspect(saved: dict | None = None) -> tuple[Identity, Identity, LiveState]:
    old = read_identity(OLD_PROVIDER)
    new = read_identity(NEW_PROVIDER)
    live = classify(old, new, saved)
    return old, new, live


def initial_metadata(old: Identity, new: Identity) -> dict:
    return {
        "scenario": "legitimate-provider-migration",
        "phase": 1,
        "old_dnskey": old.dnskey_text,
        "old_ds": old.ds_text,
        "old_tag": old.key_tag,
        "new_dnskey": new.dnskey_text,
        "new_ds": new.ds_text,
        "new_tag": new.key_tag,
        "pending_transition": None,
        "safe_after": None,
        "preannouncement": None,
        "announcement_observed": False,
        "updated_at": iso(now_utc()),
    }


def read_secret() -> str:
    path = Path(os.environ.get("TSIG_KEY_FILE", "/run/secrets/registrar.key"))
    try:
        text = path.read_text(encoding="ascii")
    except OSError as exc:
        raise MigrationError(f"cannot read TSIG key {path}: {exc}") from exc
    match = re.search(r'\bsecret\s+"([^"]+)"\s*;', text)
    if not match:
        raise MigrationError(f"no BIND-style secret found in {path}")
    return match.group(1)


def make_update() -> dns.update.Update:
    keyring = dns.tsigkeyring.from_text({TSIG_NAME: read_secret()})
    return dns.update.Update(
        TLD_ZONE,
        keyring=keyring,
        keyname=TSIG_NAME,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )


def send_update(update: dns.update.Update, label: str) -> None:
    try:
        response = dns.query.tcp(update, TLD, timeout=5)
    except dns.exception.DNSException as exc:
        raise MigrationError(f"{label} TSIG update failed: {exc}") from exc
    if response.rcode() != dns.rcode.NOERROR:
        raise MigrationError(f"{label} TSIG update was rejected: {dns.rcode.to_text(response.rcode())}")


def mark_pending(saved: dict, transition: str) -> None:
    saved["pending_transition"] = transition
    saved["updated_at"] = iso(now_utc())
    save_saved(saved)


def reconcile_completed_transition(
    saved: dict,
    old: Identity,
    new: Identity,
    live: LiveState,
    allowed: set[str],
) -> dict:
    saved_phase = saved.get("phase")
    if saved_phase == live.number:
        pending = saved.get("pending_transition")
        if pending is not None and pending not in allowed:
            raise MigrationError(
                f"saved pending transition {pending!r} belongs to the opposite recovery direction"
            )
        return saved
    transition = f"{saved_phase}-to-{live.number}"
    if saved.get("pending_transition") != transition or transition not in allowed:
        raise MigrationError(
            f"saved phase {saved_phase}, pending transition {saved.get('pending_transition')!r}, "
            f"and live state {live.number} are ambiguous"
        )
    _, old_glue_ttl = glue(OLD_NS)
    _, new_glue_ttl = glue(NEW_NS)
    saved["phase"] = live.number
    saved["pending_transition"] = None
    saved["safe_after"] = safety_deadline(
        live.ns_ttl,
        live.ds_ttl,
        live.negative_ttl,
        old.dnskey_ttl,
        new.dnskey_ttl,
        old_glue_ttl,
        new_glue_ttl,
    )
    saved["updated_at"] = iso(now_utc())
    save_saved(saved)
    print(f"reconciled completed atomic transition {transition}; restarted conservative cache hold")
    return saved


def assert_expected_state(expected: int, saved: dict) -> LiveState:
    _, _, live = inspect(saved)
    if live.number != expected:
        raise MigrationError(f"expected {STATE_NAMES[expected]}, found {STATE_NAMES[live.number]}")
    return live


def wait_for_state(expected: int, saved: dict, timeout: float = 30) -> LiveState:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return assert_expected_state(expected, saved)
        except MigrationError as exc:
            last_error = exc
            time.sleep(0.5)
    raise MigrationError(f"timed out waiting for {STATE_NAMES[expected]}: {last_error}")


def hold(saved: dict, expected: int) -> None:
    value = saved.get("safe_after")
    if not value:
        raise MigrationError("cache-safety deadline is missing")
    deadline = parse_time(value)
    while now_utc() < deadline:
        assert_expected_state(expected, saved)
        remaining = max(0, int((deadline - now_utc()).total_seconds()))
        print(f"cache-safety hold: {STATE_NAMES[expected]} ({remaining}s remaining)", flush=True)
        time.sleep(1)
    assert_expected_state(expected, saved)


def safety_deadline(*ttls: int) -> str:
    observation = int(os.environ.get("OBSERVATION_SECONDS", "5"))
    seconds = max(max(ttls), observation) + PROPAGATION_MARGIN
    return iso(now_utc() + timedelta(seconds=seconds))


def load_json_list(path: Path) -> list:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        raise MigrationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, list):
        raise MigrationError(f"{path} must contain a JSON list")
    return value


def write_json_list(path: Path, value: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def exact_preannouncement(saved: dict) -> dict:
    target_ns = saved["preannouncement"]["target_ns"]
    return {
        "domain": "victim.test",
        "new_ns": [target_ns],
        "new_ds": sorted((saved["old_ds"], saved["new_ds"])),
        "valid_until": saved["preannouncement"]["valid_until"],
    }


def require_preannouncement(saved: dict, target_ns: str) -> None:
    entry = saved.get("preannouncement")
    if not isinstance(entry, dict):
        raise MigrationError("exact migration pre-announcement is not installed")
    if entry.get("target_ns") != target_ns:
        raise MigrationError(f"pre-announcement does not target {target_ns}")
    expected = exact_preannouncement(saved)
    entries = load_json_list(preannouncements_path())
    if sum(item == expected for item in entries) != 1:
        raise MigrationError("the installed pre-announcement no longer matches the saved exact NS and DS state")
    if parse_time(expected["valid_until"]) <= now_utc():
        raise MigrationError("the migration pre-announcement has expired")


def collector_snapshot() -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    path = collector_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        snap = data["snapshots"]["victim.test"]
        return (
            snap["observed_at"],
            tuple(sorted(name.lower() for name in snap["ns"])),
            tuple(sorted(normalize_ds(value) for value in snap["ds"])),
        )
    except (FileNotFoundError, OSError, ValueError, KeyError, TypeError) as exc:
        raise MigrationError(f"collector state is unavailable or malformed: {exc}") from exc


def wait_collector_state(expected_ns: tuple[str, ...], expected_ds: tuple[str, ...], timeout: float) -> str:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            observed, nameservers, ds = collector_snapshot()
            last = (observed, nameservers, ds)
            if nameservers == expected_ns and ds == expected_ds:
                return observed
        except MigrationError as exc:
            last = str(exc)
        time.sleep(1)
    raise MigrationError(f"collector did not observe the required pre-switch DNS state: {last}")


def install_preannouncement(saved: dict, expected_phase: int, target_ns: str) -> None:
    if saved.get("phase") != expected_phase:
        raise MigrationError(f"pre-announcement requires saved phase {expected_phase}")
    live = assert_expected_state(expected_phase, saved)
    if live.parent_ds != tuple(sorted((saved["old_ds"], saved["new_ds"]))):
        raise MigrationError("an NS change may be announced only while the exact OLD+NEW DS bridge is present")
    hold(saved, expected_phase)
    interval = float(os.environ.get("COLLECTOR_INTERVAL_SECONDS", "10"))
    timeout = max(60.0, interval * 5)
    baseline_observed = wait_collector_state(live.nameservers, live.parent_ds, timeout)

    entries = load_json_list(preannouncements_path())
    if saved.get("preannouncement") and saved["preannouncement"].get("target_ns") != target_ns:
        remove_own_preannouncement(saved)
        entries = load_json_list(preannouncements_path())
    existing = [item for item in entries if item.get("domain", "").lower().rstrip(".") == "victim.test"]
    if existing and not saved.get("preannouncement"):
        raise MigrationError("an unrelated victim.test pre-announcement already exists; refusing to overwrite it")
    if not saved.get("preannouncement"):
        valid_for = int(os.environ.get("PREANNOUNCEMENT_VALID_SECONDS", "1800"))
        saved["preannouncement"] = {
            "target_ns": target_ns,
            "valid_until": iso(now_utc() + timedelta(seconds=valid_for)),
        }
        expected = exact_preannouncement(saved)
        entries = [item for item in entries if item not in existing]
        entries.append(expected)
        write_json_list(preannouncements_path(), entries)
        saved["announcement_observed"] = False
        saved["updated_at"] = iso(now_utc())
        save_saved(saved)
    require_preannouncement(saved, target_ns)

    distinct: set[str] = set()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(distinct) < 2:
        assert_expected_state(expected_phase, saved)
        require_preannouncement(saved, target_ns)
        observed, nameservers, ds = collector_snapshot()
        if nameservers == live.nameservers and ds == live.parent_ds and observed != baseline_observed:
            distinct.add(observed)
        time.sleep(1)
    if len(distinct) < 2:
        raise MigrationError(
            "collector did not complete two distinct polls after pre-announcement installation; NS was not changed"
        )
    saved["announcement_observed"] = True
    saved["announcement_observed_at"] = max(distinct)
    saved["updated_at"] = iso(now_utc())
    save_saved(saved)
    print(f"pre-announcement loaded before NS switch; collector polls={sorted(distinct)}")


def remove_own_preannouncement(saved: dict) -> None:
    if not saved.get("preannouncement"):
        return
    expected = exact_preannouncement(saved)
    path = preannouncements_path()
    entries = load_json_list(path)
    matches = [item for item in entries if item == expected]
    if len(matches) > 1:
        raise MigrationError("duplicate exact migration pre-announcements exist; refusing automatic cleanup")
    if matches:
        entries.remove(expected)
        write_json_list(path, entries)
    saved["preannouncement"] = None
    saved["announcement_observed"] = False
    saved.pop("announcement_observed_at", None)
    save_saved(saved)


def begin(saved: dict | None = None) -> dict:
    old, new, live = inspect(saved)
    if live.number != 1:
        raise MigrationError(f"begin requires {STATE_NAMES[1]}, found {STATE_NAMES[live.number]}")
    if saved is None:
        saved = initial_metadata(old, new)
        save_saved(saved)
    else:
        verify_saved_identities(saved, old, new)

    mark_pending(saved, "1-to-2")
    update = make_update()
    update.add("victim", TTL, dns.rdatatype.DS, new.ds_text)
    update.delete("ns.newprovider", dns.rdatatype.A)
    update.add("ns.newprovider", TTL, dns.rdatatype.A, NEW_GLUE)
    send_update(update, "add new-provider DS and glue")
    live = wait_for_state(2, saved)
    _, new_glue_ttl = glue(NEW_NS)
    saved["phase"] = 2
    saved["pending_transition"] = None
    saved["safe_after"] = safety_deadline(live.ds_ttl, new.dnskey_ttl, new_glue_ttl)
    saved["updated_at"] = iso(now_utc())
    save_saved(saved)
    print(f"PHASE 2: parent DS tags {old.key_tag}+{new.key_tag}; NS remains {OLD_NS}")
    return saved


def switch(saved: dict) -> dict:
    if saved.get("phase") != 2:
        raise MigrationError("NS switch requires saved phase 2")
    assert_expected_state(2, saved)
    hold(saved, 2)
    require_preannouncement(saved, NEW_NS)
    if not saved.get("announcement_observed"):
        raise MigrationError("collector observation of the pre-announcement is not proven")

    mark_pending(saved, "2-to-3")
    update = make_update()
    update.delete("victim", dns.rdatatype.NS)
    update.add("victim", TTL, dns.rdatatype.NS, NEW_NS)
    send_update(update, "switch provider NS")
    flush_unbound_zone()
    live = wait_for_state(3, saved)
    _, old_glue_ttl = glue(OLD_NS)
    _, new_glue_ttl = glue(NEW_NS)
    saved["phase"] = 3
    saved["pending_transition"] = None
    saved["safe_after"] = safety_deadline(
        live.ns_ttl, old_glue_ttl, new_glue_ttl, live.negative_ttl
    )
    saved["updated_at"] = iso(now_utc())
    save_saved(saved)
    print(f"PHASE 3: NS switched to {NEW_NS}; both DS records remain")
    return saved


def retire_old_ds(saved: dict) -> dict:
    if saved.get("phase") != 3:
        raise MigrationError("OLD DS retirement requires saved phase 3")
    assert_expected_state(3, saved)
    hold(saved, 3)
    mark_pending(saved, "3-to-4")
    update = make_update()
    update.delete("victim", dns.rdatatype.DS)
    update.add("victim", TTL, dns.rdatatype.DS, saved["new_ds"])
    send_update(update, "retire old-provider DS")
    live = wait_for_state(4, saved)
    saved["phase"] = 4
    saved["pending_transition"] = None
    saved["safe_after"] = safety_deadline(live.ds_ttl)
    saved["updated_at"] = iso(now_utc())
    save_saved(saved)
    hold(saved, 4)
    remove_own_preannouncement(saved)
    print(f"PHASE 4: migration complete; parent trusts NEW tag {saved['new_tag']} only")
    return saved


def resume() -> dict:
    saved = load_saved(required=True)
    old, new, live = inspect(saved)
    saved = reconcile_completed_transition(
        saved, old, new, live, {"1-to-2", "2-to-3", "3-to-4"}
    )
    live = assert_expected_state(saved["phase"], saved)
    if live.number == 1:
        saved = begin(saved)
        install_preannouncement(saved, 2, NEW_NS)
        saved = load_saved(required=True)
        saved = switch(saved)
        return retire_old_ds(saved)
    if live.number == 2:
        install_preannouncement(saved, 2, NEW_NS)
        saved = load_saved(required=True)
        saved = switch(saved)
        return retire_old_ds(saved)
    if live.number == 3:
        return retire_old_ds(saved)
    assert_expected_state(4, saved)
    hold(saved, 4)
    remove_own_preannouncement(saved)
    print("migration is already complete")
    return saved


def run() -> dict:
    saved = load_saved()
    if saved is None:
        old, new, live = inspect()
        if live.number != 1:
            raise MigrationError("a saved state is required to resume a transitional migration")
        saved = initial_metadata(old, new)
        save_saved(saved)
    return resume()


def reset() -> dict:
    saved = load_saved(required=True)
    old, new, live = inspect(saved)
    saved = reconcile_completed_transition(
        saved,
        old,
        new,
        live,
        {"1-to-2", "2-to-3", "3-to-4", "4-to-3", "3-to-2", "2-to-1"},
    )
    live = assert_expected_state(saved["phase"], saved)

    if live.number == 4:
        mark_pending(saved, "4-to-3")
        update = make_update()
        update.add("victim", TTL, dns.rdatatype.DS, saved["old_ds"])
        send_update(update, "reset: restore old-provider DS bridge")
        live = wait_for_state(3, saved)
        saved["phase"] = 3
        saved["pending_transition"] = None
        saved["safe_after"] = safety_deadline(live.ds_ttl)
        saved["updated_at"] = iso(now_utc())
        save_saved(saved)
        hold(saved, 3)

    if saved["phase"] == 3:
        assert_expected_state(3, saved)
        install_preannouncement(saved, 3, OLD_NS)
        saved = load_saved(required=True)
        mark_pending(saved, "3-to-2")
        update = make_update()
        update.delete("victim", dns.rdatatype.NS)
        update.add("victim", TTL, dns.rdatatype.NS, OLD_NS)
        send_update(update, "reset: switch NS to old provider")
        flush_unbound_zone()
        live = wait_for_state(2, saved)
        _, old_glue_ttl = glue(OLD_NS)
        _, new_glue_ttl = glue(NEW_NS)
        saved["phase"] = 2
        saved["pending_transition"] = None
        saved["safe_after"] = safety_deadline(
            live.ns_ttl, old_glue_ttl, new_glue_ttl, live.negative_ttl
        )
        saved["updated_at"] = iso(now_utc())
        save_saved(saved)
        hold(saved, 2)

    if saved["phase"] == 2:
        assert_expected_state(2, saved)
        mark_pending(saved, "2-to-1")
        update = make_update()
        update.delete("victim", dns.rdatatype.DS)
        update.add("victim", TTL, dns.rdatatype.DS, saved["old_ds"])
        update.delete("ns.newprovider", dns.rdatatype.A)
        send_update(update, "reset: retire new-provider DS and glue")
        live = wait_for_state(1, saved)
        saved["phase"] = 1
        saved["pending_transition"] = None
        saved["safe_after"] = safety_deadline(live.ds_ttl)
        saved["updated_at"] = iso(now_utc())
        save_saved(saved)
        hold(saved, 1)

    assert_expected_state(1, saved)
    remove_own_preannouncement(saved)
    print(f"RESET COMPLETE: {STATE_NAMES[1]}, trusted tag {saved['old_tag']}")
    return saved


def status() -> None:
    saved = load_saved()
    old, new, live = inspect(saved)
    print(f"state={live.number}: {STATE_NAMES[live.number]}")
    print(f"old DNSKEY tag={old.key_tag} DS={old.ds_text}")
    print(f"new DNSKEY tag={new.key_tag} DS={new.ds_text}")
    print(f"parent NS={','.join(live.nameservers)}")
    print(f"parent DS={' | '.join(live.parent_ds)}")
    print("Unbound=NOERROR AD=true A=192.0.2.10")
    if saved:
        print(
            f"saved phase={saved.get('phase')} safe_after={saved.get('safe_after')} "
            f"pending={saved.get('pending_transition')} "
            f"announcement_observed={saved.get('announcement_observed')}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("status", "begin", "announce", "switch", "retire-old-ds", "run", "resume", "reset"),
    )
    args = parser.parse_args()
    if args.command == "status":
        status()
    elif args.command == "begin":
        begin(load_saved())
    elif args.command == "announce":
        install_preannouncement(load_saved(required=True), 2, NEW_NS)
    elif args.command == "switch":
        switch(load_saved(required=True))
    elif args.command == "retire-old-ds":
        retire_old_ds(load_saved(required=True))
    elif args.command == "run":
        run()
    elif args.command == "resume":
        resume()
    else:
        reset()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MigrationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
