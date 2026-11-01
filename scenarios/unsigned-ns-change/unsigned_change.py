"""TSIG state controller for Scenario 8's unsigned NS-only change."""
import argparse, re, time
from pathlib import Path
import dns.dnssec, dns.flags, dns.message, dns.query, dns.rcode, dns.rdatatype
import dns.tsig, dns.tsigkeyring, dns.update

TLD='172.30.0.11'; OLD='172.30.0.12'; NEW='172.30.0.17'; ZONE='victim.test.'
OLD_NS='ns.victim.test.'; NEW_NS='ns.unsigned.test.'; TSIG='mock-registrar.'

def query(server,name,kind):
    q=dns.message.make_query(name,kind,want_dnssec=True); q.flags &= ~dns.flags.RD
    r,_=dns.query.udp_with_fallback(q,server,timeout=5)
    if r.rcode()!=dns.rcode.NOERROR: raise RuntimeError(f'{name} returned {dns.rcode.to_text(r.rcode())}')
    return r
def rr(r,kind,covers=0):
    for s in (r.answer,r.authority,r.additional):
        for x in s:
            if x.rdtype==kind and x.covers==covers:return x
    return None
def parent():
    d=rr(query(TLD,ZONE,dns.rdatatype.DS),dns.rdatatype.DS); n=rr(query(TLD,ZONE,dns.rdatatype.NS),dns.rdatatype.NS)
    return tuple(sorted(' '.join(x.to_text().split()).upper() for x in d)) if d else (),tuple(sorted(x.target.to_text().lower() for x in n))
def current_ds():
    r=query(OLD,ZONE,dns.rdatatype.DNSKEY); keys=rr(r,dns.rdatatype.DNSKEY); sig=rr(r,dns.rdatatype.RRSIG,dns.rdatatype.DNSKEY)
    if not keys or not sig: raise RuntimeError('signed provider DNSKEY is unavailable')
    dns.dnssec.validate(keys,sig,{keys.name:keys}); eligible=[k for k in keys if k.flags & 257 == 257]
    if len(eligible)!=1: raise RuntimeError('signed provider is not in a stable single-key state')
    return ' '.join(dns.dnssec.make_ds(keys.name,eligible[0],'SHA256').to_text().split()).upper()
def send(ns=None,ds_marker='keep',glue_marker='keep'):
    text=Path('/run/secrets/registrar.key').read_text(); m=re.search(r'secret\s+"([^"]+)"',text)
    ring=dns.tsigkeyring.from_text({TSIG:m.group(1)}); u=dns.update.Update('test.',keyring=ring,keyname=TSIG,keyalgorithm=dns.tsig.HMAC_SHA256)
    if ns: u.delete('victim',dns.rdatatype.NS); u.add('victim',30,dns.rdatatype.NS,ns)
    if ds_marker!='keep':
        u.delete('victim',dns.rdatatype.DS)
        if ds_marker: u.add('victim',30,dns.rdatatype.DS,ds_marker)
    if glue_marker!='keep':
        u.delete('ns.unsigned',dns.rdatatype.A)
        if glue_marker: u.add('ns.unsigned',30,dns.rdatatype.A,glue_marker)
    r=dns.query.tcp(u,TLD,timeout=5)
    if r.rcode()!=dns.rcode.NOERROR: raise RuntimeError(f'update rejected: {dns.rcode.to_text(r.rcode())}')
def wait(expected):
    end=time.monotonic()+30
    while True:
        got=parent()
        if got==expected:return
        if time.monotonic()>=end:raise RuntimeError(f'parent state {got}, expected {expected}')
        time.sleep(.5)
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['remove-ds','switch','reverse','restore-ds','status']);a=p.parse_args()
    ds,ns=parent()
    if a.command=='remove-ds':
        wanted=current_ds()
        if ns!=(OLD_NS,) or ds not in ((wanted,),()):raise RuntimeError(f'unsafe starting state: NS={ns} DS={ds}')
        if ds:send(ds_marker=None)
        wait(((),(OLD_NS,)))
    elif a.command=='switch':
        if (ds,ns)!=((),(OLD_NS,)):raise RuntimeError(f'unsafe switch state: NS={ns} DS={ds}')
        send(ns=NEW_NS,glue_marker='172.30.0.17');wait(((),(NEW_NS,)))
    elif a.command=='reverse':
        if (ds,ns)==((),(NEW_NS,)):send(ns=OLD_NS,glue_marker=None)
        elif ns==(OLD_NS,) and ds:
            print(f'parent_ns={ns} parent_ds={ds} (already restored)')
            return
        elif (ds,ns)!=((),(OLD_NS,)):raise RuntimeError(f'unsafe reverse state: NS={ns} DS={ds}')
        wait(((),(OLD_NS,)))
    elif a.command=='restore-ds':
        wanted=current_ds()
        if ns!=(OLD_NS,) or ds not in ((),(wanted,)):raise RuntimeError(f'unsafe restore state: NS={ns} DS={ds}')
        if not ds:send(ds_marker=wanted)
        wait(((wanted,),(OLD_NS,)))
    print(f'parent_ns={parent()[1]} parent_ds={parent()[0] or "<empty>"}')
if __name__=='__main__':main()
