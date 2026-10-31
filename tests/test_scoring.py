"""Scoring v1 (spec sections 5 and 8) on in-memory signed snapshots: no lab, no zone files."""
from datetime import datetime, timedelta, timezone

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec

from collector.snapshot import diff
from scoring.rules import empty_history, score, update_history

NAME = dns.name.from_text("victim.test.")
IN = dns.rdataclass.IN
TTL = 30
NOW = datetime.now(timezone.utc)
PROV, ATT, NEWPROV = ["ns.victim.test."], ["ns.attacker.test."], ["ns.newprovider.test."]


class Key:
    """A synthetic ECDSA P-256 key (algorithm 13) with its DS (digest type 2)."""
    def __init__(self, flags=257):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.dnskey = dns.dnssec.make_dnskey(self.private.public_key(), 13, flags=flags)
        self.ds = dns.dnssec.make_ds(NAME, self.dnskey, "SHA256")


def _rrset(rdatas):
    return dns.rrset.from_rdata_list(NAME, TTL, rdatas) if rdatas else None


def _sign(rrset, signers):
    if rrset is None or not signers:
        return None
    sigs = [dns.dnssec.sign(rrset, k.private, NAME, k.dnskey,
                            inception=NOW - timedelta(hours=1), expiration=NOW + timedelta(days=1))
            for k in signers]
    return dns.rrset.from_rdata_list(NAME, TTL, sigs)


def _texts(rrset):
    return sorted(r.to_text() for r in rrset) if rrset else []


def snap(i, ns, ds, keys, signers=None, cds=(), cds_signers=None):
    """Snapshot like collector.snapshot produces. signers = keys that sign the DNSKEY set."""
    signers = [k for k in keys if k.dnskey.flags == 257] if signers is None else signers
    cds_signers = signers if cds_signers is None else cds_signers
    ds_set = _rrset([k.ds for k in ds])
    key_set = _rrset([k.dnskey for k in keys])
    cds_set = _rrset([dns.rdata.from_text(IN, dns.rdatatype.CDS, k.ds.to_text()) for k in cds])
    return {"domain": "victim.test", "observed_at": f"2026-11-14T10:{i:02d}:00Z",
            "ns": sorted(ns), "ds": _texts(ds_set), "dnskey": _texts(key_set), "cds": _texts(cds_set),
            "_raw": {"ds": ds_set, "ds_rrsig": None,
                     "dnskey": key_set, "dnskey_rrsig": _sign(key_set, signers),
                     "cds": cds_set, "cds_rrsig": _sign(cds_set, cds_signers)}}


def run(snaps, pre=()):
    """Feed snapshots like the collector loop: diff -> score (old history) -> update history."""
    history, prev, out = empty_history(), None, []
    for s in snaps:
        obs = diff(prev, s)
        if obs:
            out.append((obs["changes"], score(obs, history, s, pre)["risk"]))
        history = update_history(history, s)
        prev = s
    return out


def risks(results):
    return [r for _, r in results]


# ---------- spec section 8 scenarios ----------

def test_1_zsk_rollover_is_low():
    ksk, zsk1, zsk2 = Key(), Key(256), Key(256)
    out = run([snap(0, PROV, [ksk], [ksk, zsk1]),
               snap(1, PROV, [ksk], [ksk, zsk2])])
    assert out == [(["DNSKEY_CHANGED"], "low")]


def test_2_double_ksk_rollover_is_low():
    old, new = Key(), Key()
    out = run([snap(0, PROV, [old], [old]),
               snap(1, PROV, [old], [old, new]),   # new KSK published, signed by the old one
               snap(2, PROV, [new], [old, new]),   # DS swapped: trail seen one poll earlier
               snap(3, PROV, [new], [new])])       # old KSK removed
    assert [c for c, _ in out] == [["DNSKEY_CHANGED"], ["DS_REPLACED"], ["DNSKEY_CHANGED"]]
    assert risks(out) == ["low", "low", "low"]


def test_3_double_ds_rollover_is_low():
    old, new = Key(), Key()
    out = run([snap(0, PROV, [old], [old]),
               snap(1, PROV, [old, new], [old]),   # new DS added next to the old one
               snap(2, PROV, [old, new], [new]),   # key swapped
               snap(3, PROV, [new], [new])])       # old DS removed
    assert [c for c, _ in out] == [["DS_ADDED"], ["DNSKEY_CHANGED"], ["DS_REMOVED"]]
    assert risks(out) == ["low", "low", "low"]


def test_4_cds_driven_rollover_is_low():
    old, new = Key(), Key()
    out = run([snap(0, PROV, [old], [old]),
               snap(1, PROV, [old], [old, new], cds=[new]),       # CDS signed by the old key
               snap(2, PROV, [new], [old, new], cds=[new])])      # registrar follows the CDS
    assert "CDS_PUBLISHED" in out[0][0] and out[1][0] == ["DS_REPLACED"]
    assert risks(out) == ["low", "low"]


def test_5a_provider_migration_is_high():
    old, new = Key(), Key()
    out = run([snap(0, PROV, [old], [old]), snap(1, NEWPROV, [new], [new])])
    assert risks(out) == ["high"]


def test_5b_preannounced_migration_is_low():
    old, new = Key(), Key()
    pre = [{"domain": "victim.test", "new_ns": NEWPROV, "new_ds": [new.ds.to_text()],
            "valid_until": "2026-11-14T12:00:00Z"}]
    out = run([snap(0, PROV, [old], [old]), snap(1, NEWPROV, [new], [new])], pre)
    assert risks(out) == ["low"]


def test_5b_expired_preannouncement_is_high():
    old, new = Key(), Key()
    pre = [{"domain": "victim.test", "new_ns": NEWPROV, "valid_until": "2026-11-14T09:00:00Z"}]
    out = run([snap(0, PROV, [old], [old]), snap(1, NEWPROV, [new], [new])], pre)
    assert risks(out) == ["high"]


def test_6_registrar_hijack_is_high():
    prov, att = Key(), Key()
    out = run([snap(0, PROV, [prov], [prov]), snap(1, ATT, [att], [att])])
    assert out == [(["NS_CHANGED", "DS_REPLACED", "DNSKEY_CHANGED"], "high")]


def test_7_ds_removal_is_high():
    prov = Key()
    out = run([snap(0, PROV, [prov], [prov]), snap(1, ATT, [], [])])
    assert "DS_ALL_REMOVED" in out[0][0] and risks(out) == ["high"]


def test_8_ns_change_unsigned_is_medium():
    out = run([snap(0, PROV, [], []), snap(1, ATT, [], [])])
    assert out == [(["NS_CHANGED"], "medium")]


# ---------- attacks the spec warns about ----------

def test_trail_in_the_same_poll_does_not_count():
    old, new = Key(), Key()
    out = run([snap(0, PROV, [old], [old]),
               snap(1, PROV, [new], [old, new])])  # new key and DS swap in one poll
    assert risks(out) == ["high"]


def test_trail_signed_only_by_attacker_does_not_count():
    old, att = Key(), Key()
    out = run([snap(0, PROV, [old], [old]),
               snap(1, PROV, [old], [old, att], signers=[att]),  # fake trail, not signed by old
               snap(2, PROV, [att], [old, att], signers=[att])])
    assert out[-1] == (["DS_REPLACED"], "high")