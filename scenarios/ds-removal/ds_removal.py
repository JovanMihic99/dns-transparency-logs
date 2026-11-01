"""Scenario 7: remove and safely restore the victim.test parent DS RRset."""
import argparse, re, time
from pathlib import Path
import dns.dnssec, dns.flags, dns.message, dns.query, dns.rcode, dns.rdatatype
import dns.tsig, dns.tsigkeyring, dns.update

TLD = "172.30.0.11"; PROVIDER = "172.30.0.12"; ZONE = "victim.test."; TSIG_NAME = "mock-registrar."

def query(server, name, kind):
    q = dns.message.make_query(name, kind, want_dnssec=True); q.flags &= ~dns.flags.RD
    r, _ = dns.query.udp_with_fallback(q, server, timeout=5)
    if r.rcode() != dns.rcode.NOERROR: raise RuntimeError(f"{name} {kind} returned {dns.rcode.to_text(r.rcode())}")
    return r

def rrset(response, kind, covers=0):
    for section in (response.answer, response.authority):
        for value in section:
            if value.rdtype == kind and value.covers == covers: return value
    return None

def identity():
    r = query(PROVIDER, ZONE, dns.rdatatype.DNSKEY)
    keys, sigs = rrset(r, dns.rdatatype.DNSKEY), rrset(r, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)
    if not keys or not sigs: raise RuntimeError("provider DNSKEY RRset or signature is missing")
    dns.dnssec.validate(keys, sigs, {keys.name: keys})
    eligible = [k for k in keys if k.flags & 257 == 257]
    if len(eligible) != 1: raise RuntimeError(f"expected one eligible provider key, found {len(eligible)}")
    key = eligible[0]; ds = dns.dnssec.make_ds(keys.name, key, "SHA256")
    return dns.dnssec.key_id(key), " ".join(ds.to_text().split()).upper()

def parent():
    dsr = query(TLD, ZONE, dns.rdatatype.DS); ds = rrset(dsr, dns.rdatatype.DS)
    nsr = query(TLD, ZONE, dns.rdatatype.NS); ns = rrset(nsr, dns.rdatatype.NS)
    return tuple(sorted(" ".join(x.to_text().split()).upper() for x in ds)) if ds else (), tuple(sorted(x.target.to_text().lower() for x in ns))

def send(wanted):
    text = Path('/run/secrets/registrar.key').read_text(); match = re.search(r'secret\s+"([^"]+)"', text)
    if not match: raise RuntimeError("TSIG secret is malformed")
    ring = dns.tsigkeyring.from_text({TSIG_NAME: match.group(1)})
    u = dns.update.Update('test.', keyring=ring, keyname=TSIG_NAME, keyalgorithm=dns.tsig.HMAC_SHA256)
    u.delete('victim', dns.rdatatype.DS)
    if wanted: u.add('victim', 30, dns.rdatatype.DS, wanted)
    r = dns.query.tcp(u, TLD, timeout=5)
    if r.rcode() != dns.rcode.NOERROR: raise RuntimeError(f"TSIG update rejected: {dns.rcode.to_text(r.rcode())}")

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('command', choices=['status','remove','restore']); args=parser.parse_args()
    tag, expected = identity(); before, ns = parent()
    if ns != ('ns.victim.test.',): raise RuntimeError(f"refusing unexpected NS state: {ns}")
    if args.command == 'remove':
        if before and before != (expected,): raise RuntimeError(f"refusing unexpected DS state: {before}")
        if before: send(None)
    elif args.command == 'restore':
        if before not in ((), (expected,)): raise RuntimeError(f"refusing unexpected DS state: {before}")
        if before != (expected,): send(expected)
    wanted = () if args.command == 'remove' else before if args.command == 'status' else (expected,)
    deadline = time.monotonic() + 30
    while True:
        after, ns = parent()
        if after == wanted or args.command == 'status' or time.monotonic() >= deadline: break
        time.sleep(0.5)
    if after != wanted: raise RuntimeError(f"postcondition failed: DS={after}, expected={wanted}")
    print(f"provider_tag={tag} provider_ds={expected}"); print(f"parent_ns={','.join(ns)} parent_ds={' | '.join(after) or '<empty>'}")

if __name__ == '__main__': main()
