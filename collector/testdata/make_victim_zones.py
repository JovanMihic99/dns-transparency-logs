"""Generate sample zone files for victim.test, before and after a registrar hijack.

Synthetic lab data only (.test is reserved for testing, RFC 6761).
Run once and commit the output; rerunning creates new keys (use --force).
The files are unsigned (no RRSIGs); signed versions come later for the scoring tests.
"""
import sys
from pathlib import Path

import dns.dnssec
import dns.name
from cryptography.hazmat.primitives.asymmetric import ec

OUT = Path(__file__).parent
VICTIM = dns.name.from_text("victim.test.")
ALG = 13  # ECDSAP256SHA256, spec section 2

PARENT = """$ORIGIN test.
$TTL 30
@             IN SOA ns.test. hostmaster.test. 1 30 30 300 30
@             IN NS  ns.test.
ns            IN A   10.53.0.11
ns1.provider  IN A   10.53.0.12
ns1.attacker  IN A   10.53.0.13
victim        IN NS  {ns}
victim        IN DS  {ds}
"""

CHILD = """$ORIGIN victim.test.
$TTL 30
@   IN SOA {ns} hostmaster.victim.test. 1 30 30 300 30
@   IN NS  {ns}
@   IN DNSKEY {ksk}
@   IN DNSKEY {zsk}
@   IN A   {addr}
"""


def make_keys():
    """KSK (flags 257) + ZSK (flags 256), and the DS (digest type 2) for the KSK."""
    ksk = dns.dnssec.make_dnskey(ec.generate_private_key(ec.SECP256R1()).public_key(), ALG, flags=257)
    zsk = dns.dnssec.make_dnskey(ec.generate_private_key(ec.SECP256R1()).public_key(), ALG, flags=256)
    ds = dns.dnssec.make_ds(VICTIM, ksk, "SHA256")
    return ksk, zsk, ds


def main():
    p_ksk, p_zsk, p_ds = make_keys()  # legitimate provider
    a_ksk, a_zsk, a_ds = make_keys()  # attacker
    files = {
        "test.before.zone": PARENT.format(ns="ns1.provider.test.", ds=p_ds.to_text()),
        "test.after.zone": PARENT.format(ns="ns1.attacker.test.", ds=a_ds.to_text()),
        "victim.provider.zone": CHILD.format(ns="ns1.provider.test.", ksk=p_ksk.to_text(),
                                             zsk=p_zsk.to_text(), addr="192.0.2.10"),
        "victim.attacker.zone": CHILD.format(ns="ns1.attacker.test.", ksk=a_ksk.to_text(),
                                             zsk=a_zsk.to_text(), addr="198.51.100.66"),
    }
    if any((OUT / f).exists() for f in files) and "--force" not in sys.argv:
        sys.exit("Zone files already exist; rerun with --force to regenerate (new keys).")
    for fname, text in files.items():
        (OUT / fname).write_text(text)
        print("wrote", OUT / fname)


if __name__ == "__main__":
    main()