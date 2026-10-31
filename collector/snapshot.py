"""LoKey collector: snapshots and diffs (LoKey_spec.md sections 3 and 4).

Snapshot = {domain, observed_at, ns, ds, dnskey, cds}: sorted lists in
presentation format. It also carries "_raw": the dnspython RRsets plus their
RRSIGs, for scoring (trail validation). "_raw" is never put into an
observation and never goes into the log.
"""
from datetime import datetime, timezone

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.zone

TIMEOUT = 3.0
FIELDS = ("ns", "ds", "dnskey", "cds")
IN = dns.rdataclass.IN
RT = dns.rdatatype


class CollectorError(Exception):
    """A query failed. Skip this poll: a failure must never look like 'records removed'."""


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _texts(rrset):
    return sorted(rr.to_text() for rr in rrset) if rrset else []


def _snapshot(domain, observed_at, ns, ds, ds_sig, dnskey, dnskey_sig, cds, cds_sig):
    return {
        "domain": domain.rstrip(".").lower(),
        "observed_at": observed_at,
        "ns": _texts(ns),
        "ds": _texts(ds),
        "dnskey": _texts(dnskey),
        "cds": _texts(cds),
        "_raw": {
            "ds": ds, "ds_rrsig": ds_sig,
            "dnskey": dnskey, "dnskey_rrsig": dnskey_sig,
            "cds": cds, "cds_rrsig": cds_sig,
        },
    }


# ---------- live mode ----------

def _query(qname, rdtype, server):
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    q.flags &= ~dns.flags.RD  # RD off: we talk to authoritative servers only
    what = f"{qname} {dns.rdatatype.to_text(rdtype)} @{server}"
    try:
        resp, _ = dns.query.udp_with_fallback(q, server, timeout=TIMEOUT)  # TCP if truncated
    except Exception as e:
        raise CollectorError(f"{what}: {e}") from e
    if resp.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        raise CollectorError(f"{what}: rcode {dns.rcode.to_text(resp.rcode())}")
    return resp


def _get(resp, section, name, rdtype, covers=RT.NONE):
    return resp.get_rrset(section, name, IN, rdtype, covers)


def _ns_addresses(referral, ns_names, tld_ip):
    """Glue from the referral's additional section; else ask the tld server. IPv4 only (lab)."""
    addrs = []
    for ns in ns_names:
        glue = _get(referral, referral.additional, ns, RT.A)
        if not glue:
            r = _query(ns, RT.A, tld_ip)
            glue = _get(r, r.answer, ns, RT.A)
        if glue:
            addrs += [rr.address for rr in glue]
    return addrs


def _child_records(name, addrs):
    """DNSKEY and CDS (+ RRSIGs) from the first of the domain's own servers that answers."""
    last = None
    for addr in addrs:
        try:
            rk = _query(name, RT.DNSKEY, addr)
            rc = _query(name, RT.CDS, addr)
        except CollectorError as e:
            last = e
            continue
        return (_get(rk, rk.answer, name, RT.DNSKEY),
                _get(rk, rk.answer, name, RT.RRSIG, RT.DNSKEY),
                _get(rc, rc.answer, name, RT.CDS),
                _get(rc, rc.answer, name, RT.RRSIG, RT.CDS))
    raise last


def take_snapshot_live(domain, tld_ip):
    name = dns.name.from_text(domain)
    observed_at = _now()

    # DS: authoritative answer from the tld server
    r = _query(name, RT.DS, tld_ip)
    ds = _get(r, r.answer, name, RT.DS)
    ds_sig = _get(r, r.answer, name, RT.RRSIG, RT.DS)

    # NS: referral, so read the authority section
    ref = _query(name, RT.NS, tld_ip)
    ns = _get(ref, ref.authority, name, RT.NS)

    dnskey = dnskey_sig = cds = cds_sig = None
    if ns:
        addrs = _ns_addresses(ref, [rr.target for rr in ns], tld_ip)
        if not addrs:
            raise CollectorError(f"no addresses for the name servers of {domain}")
        dnskey, dnskey_sig, cds, cds_sig = _child_records(name, addrs)

    return _snapshot(domain, observed_at, ns, ds, ds_sig, dnskey, dnskey_sig, cds, cds_sig)


# ---------- file mode (testing before the lab is up) ----------

def take_snapshot_from_files(domain, parent_zone_file, child_zone_file, observed_at=None):
    """parent_zone_file = the .test zone; child_zone_file = the domain's zone, or None if absent."""
    name = dns.name.from_text(domain)
    parent = dns.zone.from_file(parent_zone_file, origin=name.parent(), relativize=False)
    ns = parent.get_rrset(name, RT.NS)
    ds = parent.get_rrset(name, RT.DS)
    ds_sig = parent.get_rrset(name, RT.RRSIG, RT.DS)

    dnskey = dnskey_sig = cds = cds_sig = None
    if child_zone_file:
        child = dns.zone.from_file(child_zone_file, origin=name, relativize=False)
        dnskey = child.get_rrset(name, RT.DNSKEY)
        dnskey_sig = child.get_rrset(name, RT.RRSIG, RT.DNSKEY)
        cds = child.get_rrset(name, RT.CDS)
        cds_sig = child.get_rrset(name, RT.RRSIG, RT.CDS)

    return _snapshot(domain, observed_at or _now(), ns, ds, ds_sig, dnskey, dnskey_sig, cds, cds_sig)


# ---------- diff ----------

def _ds_change(old, new):
    o, n = set(old), set(new)
    if o == n:
        return None
    if not n:
        return "DS_ALL_REMOVED"
    added, removed = n - o, o - n
    if added and removed:
        return "DS_REPLACED"
    return "DS_ADDED" if added else "DS_REMOVED"


def diff(old, new):
    """Observation in the spec section 4 format, or None. The first poll (old=None) is the baseline."""
    if old is None:
        return None
    if old["domain"] != new["domain"]:
        raise ValueError("diff() called with snapshots of two different domains")

    changes = []
    if old["ns"] != new["ns"]:
        changes.append("NS_CHANGED")
    ds = _ds_change(old["ds"], new["ds"])
    if ds:
        changes.append(ds)
    if old["dnskey"] != new["dnskey"]:
        changes.append("DNSKEY_CHANGED")
    if old["cds"] != new["cds"]:
        o, n = set(old["cds"]), set(new["cds"])
        if n - o:
           changes.append("CDS_PUBLISHED")  # new CDS record(s) appeared
        if o - n:
            changes.append("CDS_REMOVED")    # CDS record(s) disappeared (some or all)
    if not changes:
        return None

    return {
        "domain": new["domain"],
        "observed_at": new["observed_at"],
        "changes": changes,
        "before": {f: list(old[f]) for f in FIELDS},
        "after": {f: list(new[f]) for f in FIELDS},
    }