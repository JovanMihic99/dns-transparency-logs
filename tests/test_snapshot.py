"""Registrar hijack (spec section 8, scenario 6) on static zone files."""
import json
from pathlib import Path

import dns.dnssec
import dns.name

from collector.snapshot import diff, take_snapshot_from_files

D = Path(__file__).resolve().parent.parent / "collector" / "testdata"
VICTIM = dns.name.from_text("victim.test.")


def snap(parent, child, t):
    # str(): dns.zone.from_file treats anything that isn't a str as an open file
    return take_snapshot_from_files("victim.test", str(D / parent), str(D / child), observed_at=t)


def before():
    return snap("test.before.zone", "victim.provider.zone", "2026-11-14T10:32:00Z")


def after():
    return snap("test.after.zone", "victim.attacker.zone", "2026-11-14T10:32:10Z")


def test_hijack_produces_ns_changed_and_ds_replaced():
    obs = diff(before(), after())
    assert obs is not None
    assert {"NS_CHANGED", "DS_REPLACED"} <= set(obs["changes"])
    assert obs["changes"][:2] == ["NS_CHANGED", "DS_REPLACED"]
    assert obs["domain"] == "victim.test"
    assert obs["observed_at"] == "2026-11-14T10:32:10Z"
    assert obs["before"]["ns"] == ["ns1.provider.test."]
    assert obs["after"]["ns"] == ["ns1.attacker.test."]


def test_no_change_and_first_poll_give_none():
    assert diff(before(), before()) is None
    assert diff(None, before()) is None


def test_observation_is_canonical_json_without_raw():
    obs = diff(before(), after())
    assert set(obs) == {"domain", "observed_at", "changes", "before", "after"}
    for side in ("before", "after"):
        assert set(obs[side]) == {"ns", "ds", "dnskey", "cds"}
    json.dumps(obs, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def test_provider_ds_matches_its_ksk():
    raw = before()["_raw"]
    assert any(dns.dnssec.make_ds(VICTIM, k, "SHA256") in raw["ds"] for k in raw["dnskey"])