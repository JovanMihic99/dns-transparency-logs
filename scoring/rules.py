"""LoKey scoring rules v1 (LoKey_spec.md section 5).

Key continuity: a legitimate DS change leaves a trail signed by the previously trusted key
and seen at least one poll BEFORE the change. Call score() with the history from earlier
polls, then update_history() with the new snapshot. History is plain JSON (persistable).
"""
from datetime import datetime

import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

RULES_VERSION = "v1"
SEVERITY = {"low": 0, "medium": 1, "high": 2}
IN = dns.rdataclass.IN
DS_CHANGES = {"DS_ADDED", "DS_REMOVED", "DS_ALL_REMOVED", "DS_REPLACED"}
CDS_DELETE = "0 0 0 00"  # RFC 8078: "please remove all DS"


def empty_history():
    return {"trusted": [], "trail_keys": [], "trail_cds": []}


# ---------- DNSSEC helpers ----------

def _rdata(rdtype, text):
    return dns.rdata.from_text(IN, rdtype, text)


def _norm(text):
    return " ".join(text.split()).lower()


def _validates(rrset, rrsig, name, key_texts):
    """True if the RRset's signatures validate with at least one of the given DNSKEYs."""
    if not rrset or not rrsig or not key_texts:
        return False
    keys = dns.rrset.from_rdata_list(name, 30, [_rdata(dns.rdatatype.DNSKEY, k) for k in key_texts])
    try:
        dns.dnssec.validate(rrset, rrsig, {name: keys})
        return True
    except dns.exception.DNSException:
        return False


def _ds_matches_key(name, ds_text, key_text):
    ds = _rdata(dns.rdatatype.DS, ds_text)
    try:
        return dns.dnssec.make_ds(name, _rdata(dns.rdatatype.DNSKEY, key_text), ds.digest_type) == ds
    except (dns.exception.DNSException, ValueError):
        return False


def trusted_keys(snap):
    """Spec: a DNSKEY that matches a DS at the parent and whose DNSKEY RRset validated with it."""
    raw = snap.get("_raw") or {}
    name = dns.name.from_text(snap["domain"])
    return sorted(k for k in snap["dnskey"]
                  if any(_ds_matches_key(name, d, k) for d in snap["ds"])
                  and _validates(raw.get("dnskey"), raw.get("dnskey_rrsig"), name, [k]))


def _has_trail(name, ds_text, history):
    return (any(_ds_matches_key(name, ds_text, k) for k in history["trail_keys"])
            or _norm(ds_text) in history["trail_cds"])


# ---------- history ----------

def update_history(history, snap):
    """Call after every poll (also the baseline), AFTER score()."""
    raw = snap.get("_raw") or {}
    name = dns.name.from_text(snap["domain"])
    now_trusted = trusted_keys(snap)
    signers = sorted(set(history["trusted"]) | set(now_trusted))
    trail_keys, trail_cds = set(history["trail_keys"]), set(history["trail_cds"])
    if _validates(raw.get("dnskey"), raw.get("dnskey_rrsig"), name, signers):
        trail_keys |= set(snap["dnskey"])  # published in a set signed by a trusted key
    if snap["cds"] and _validates(raw.get("cds"), raw.get("cds_rrsig"), name, signers):
        trail_cds |= {_norm(c) for c in snap["cds"]}
    return {"trusted": now_trusted, "trail_keys": sorted(trail_keys), "trail_cds": sorted(trail_cds)}


# ---------- pre-announcements ----------

def _time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _ns(n):
    return n.lower().rstrip(".") + "."


def _matching_preannouncement(obs, preannouncements):
    """{domain, new_ns: [...], new_ds: [...] (optional), valid_until} matching this change."""
    for p in preannouncements:
        if p.get("domain", "").lower().rstrip(".") != obs["domain"]:
            continue
        if _time(obs["observed_at"]) > _time(p["valid_until"]):
            continue
        if sorted(map(_ns, p.get("new_ns", []))) != sorted(map(_ns, obs["after"]["ns"])):
            continue
        if p.get("new_ds") is not None and \
                sorted(map(_norm, p["new_ds"])) != sorted(map(_norm, obs["after"]["ds"])):
            continue
        return p
    return None


# ---------- scoring ----------

def _result(findings):
    findings = sorted(findings, key=lambda f: -SEVERITY[f[0]])
    return {"risk": findings[0][0], "reasons": [r for _, r in findings], "rules_version": RULES_VERSION}


def score(obs, history, snap=None, preannouncements=()):
    """Assessment for one observation. `history` must come from EARLIER polls only."""
    name = dns.name.from_text(obs["domain"])
    ch = set(obs["changes"])
    before, after = obs["before"], obs["after"]
    ds_changed = bool(ch & DS_CHANGES)
    now_trusted = trusted_keys(snap) if snap else []
    findings = []

    # NS (with or without DS) and pre-announcements
    if "NS_CHANGED" in ch:
        pre = _matching_preannouncement(obs, preannouncements)
        if pre:
            return _result([("low", f"change matches a pre-announcement valid until {pre['valid_until']}")])
        if ds_changed:
            findings.append(("high", "NS changed at the same time, not pre-announced"))
        elif before["ds"] or after["ds"]:
            findings.append(("medium", "NS changed on a signed domain, DS unchanged"))
        else:
            findings.append(("medium", "NS changed on an unsigned domain"))

    # DS
    if "DS_REPLACED" in ch:
        added = sorted(set(after["ds"]) - set(before["ds"]))
        if all(_has_trail(name, d, history) for d in added):
            findings.append(("low", "DS replaced with a key that has a trail signed by the previously trusted key"))
        else:
            findings.append(("high", "DS replaced with no trail signed by the previously trusted key"))
    elif "DS_ALL_REMOVED" in ch:
        if CDS_DELETE in history["trail_cds"]:
            findings.append(("low", "all DS removed after a CDS delete request signed by the trusted key"))
        else:
            findings.append(("high", "all DS removed with no trail signed by the previously trusted key"))
    elif "DS_ADDED" in ch:
        findings.append(("low", "new DS added while the old DS stays"))
    elif "DS_REMOVED" in ch:
        if any(_ds_matches_key(name, d, k) for d in after["ds"] for k in after["dnskey"]):
            findings.append(("low", "old DS removed, a remaining DS still matches the zone's current key"))
        else:
            findings.append(("medium", "DS removed and no remaining DS matches a current key (validation will fail)"))

    # DNSKEY (only on its own: with a DS change it is explained by the DS rule above)
    if "DNSKEY_CHANGED" in ch and not ds_changed:
        if not after["ds"]:
            findings.append(("low", "DNSKEY set changed on a domain without DS"))
        elif now_trusted:
            findings.append(("low", "DNSKEY set changed, still signed by a key matching a current DS"))
        else:
            findings.append(("medium", "DNSKEY set changed and no longer validates under the parent DS"))

    # CDS
    if "CDS_PUBLISHED" in ch:
        raw = (snap or {}).get("_raw") or {}
        signers = sorted(set(history["trusted"]) | set(now_trusted))
        if _validates(raw.get("cds"), raw.get("cds_rrsig"), name, signers):
            findings.append(("low", "CDS published, signed by the trusted key"))
        else:
            findings.append(("medium", "CDS published but not signed by a trusted key"))
    if "CDS_REMOVED" in ch:
        findings.append(("low", "CDS removed"))

    return _result(findings or [("low", "no security-relevant change")])