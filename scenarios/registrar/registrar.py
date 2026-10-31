#!/usr/bin/env python3
"""TSIG-protected mock registrar for the isolated LoKey .test lab."""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update


TLD_SERVER = "172.30.0.11"
PROVIDER_SERVER = "172.30.0.12"
ATTACKER_SERVER = "172.30.0.13"
UNBOUND_SERVER = "172.30.0.14"
TLD_ZONE = "test."
CHILD_ZONE = "victim.test."
TSIG_NAME = "mock-registrar."
TTL = 30


@dataclass(frozen=True)
class Target:
    name: str
    server: str
    nameserver: str
    address: str


TARGETS = {
    "provider": Target("provider", PROVIDER_SERVER, "ns.victim.test.", "192.0.2.10"),
    "attacker": Target("attacker", ATTACKER_SERVER, "ns.attacker.test.", "192.0.2.66"),
}


class RegistrarError(RuntimeError):
    pass


def query(server: str, owner: str, rdtype: dns.rdatatype.RdataType) -> dns.message.Message:
    request = dns.message.make_query(owner, rdtype, want_dnssec=True)
    try:
        return dns.query.udp(request, server, timeout=4)
    except dns.exception.DNSException as exc:
        raise RegistrarError(f"DNS query to {server} for {owner} failed: {exc}") from exc


def records(
    response: dns.message.Message,
    owner: str,
    rdtype: dns.rdatatype.RdataType,
) -> list:
    wanted = dns.name.from_text(owner)
    found = []
    for section in (response.answer, response.authority, response.additional):
        for rrset in section:
            if rrset.name == wanted and rrset.rdtype == rdtype:
                found.extend(rrset)
    return found


def has_signature(
    response: dns.message.Message,
    owner: str,
    covered_type: dns.rdatatype.RdataType,
) -> bool:
    for signature in records(response, owner, dns.rdatatype.RRSIG):
        if signature.covers() == covered_type:
            return True
    return False


def derive_ds(target: Target) -> list:
    response = query(target.server, CHILD_ZONE, dns.rdatatype.DNSKEY)
    keys = records(response, CHILD_ZONE, dns.rdatatype.DNSKEY)
    if not keys or not has_signature(response, CHILD_ZONE, dns.rdatatype.DNSKEY):
        raise RegistrarError(f"{target.name} does not publish a signed DNSKEY RRset")

    child_name = dns.name.from_text(CHILD_ZONE)
    ds_records = [
        dns.dnssec.make_ds(child_name, key, "SHA256")
        for key in keys
        if key.flags & 0x0001
    ]
    if not ds_records:
        raise RegistrarError(f"{target.name} has no SEP/KSK/CSK DNSKEY")
    return sorted(ds_records, key=lambda item: item.to_text())


def parse_tsig_secret() -> str:
    key_file = Path(os.environ.get("TSIG_KEY_FILE", "/run/secrets/registrar.key"))
    try:
        contents = key_file.read_text(encoding="ascii")
    except OSError as exc:
        raise RegistrarError(f"Could not read TSIG key file {key_file}: {exc}") from exc
    match = re.search(r'\bsecret\s+"([^"]+)"\s*;', contents)
    if not match:
        raise RegistrarError(f"No BIND-style secret was found in {key_file}")
    return match.group(1)


def parent_state() -> tuple[list[str], list[str], bool]:
    ns_response = query(TLD_SERVER, CHILD_ZONE, dns.rdatatype.NS)
    ds_response = query(TLD_SERVER, CHILD_ZONE, dns.rdatatype.DS)
    nameservers = sorted(item.target.to_text() for item in records(ns_response, CHILD_ZONE, dns.rdatatype.NS))
    ds_text = sorted(item.to_text() for item in records(ds_response, CHILD_ZONE, dns.rdatatype.DS))
    return nameservers, ds_text, has_signature(ds_response, CHILD_ZONE, dns.rdatatype.DS)


def expected_ds_text(target: Target) -> list[str]:
    return [item.to_text() for item in derive_ds(target)]


def wait_for_parent(target: Target) -> None:
    expected_ds = expected_ds_text(target)
    for _ in range(60):
        nameservers, ds_text, ds_signed = parent_state()
        if nameservers == [target.nameserver] and ds_text == expected_ds and ds_signed:
            return
        time.sleep(0.5)
    raise RegistrarError(f"Timed out waiting for the TLD to publish and sign the {target.name} delegation")


def apply_target(target: Target) -> None:
    secret = parse_tsig_secret()
    keyring = dns.tsigkeyring.from_text({TSIG_NAME: secret})
    update = dns.update.Update(
        TLD_ZONE,
        keyring=keyring,
        keyname=TSIG_NAME,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )

    update.delete("victim", dns.rdatatype.NS)
    update.delete("victim", dns.rdatatype.DS)
    update.delete("ns.attacker", dns.rdatatype.A)
    update.add("victim", TTL, dns.rdatatype.NS, target.nameserver)
    for ds_record in derive_ds(target):
        update.add("victim", TTL, ds_record)
    if target.name == "attacker":
        update.add("ns.attacker", TTL, dns.rdatatype.A, ATTACKER_SERVER)

    try:
        response = dns.query.tcp(update, TLD_SERVER, timeout=5)
    except dns.exception.DNSException as exc:
        raise RegistrarError(f"TSIG update failed: {exc}") from exc
    if response.rcode() != dns.rcode.NOERROR:
        raise RegistrarError(f"TLD rejected the TSIG update: {dns.rcode.to_text(response.rcode())}")

    wait_for_parent(target)
    print(f"Parent delegation now points to the {target.name} and has a matching signed DS.")
    print("Restart Unbound (or wait for caches to expire) before checking the recursive answer.")


def unbound_state() -> tuple[str, bool, str]:
    response = query(UNBOUND_SERVER, "www.victim.test.", dns.rdatatype.A)
    rcode = dns.rcode.to_text(response.rcode())
    addresses = [item.address for item in records(response, "www.victim.test.", dns.rdatatype.A)]
    return rcode, bool(response.flags & dns.flags.AD), ", ".join(addresses) if addresses else "(none)"


def status() -> int:
    provider_ds = expected_ds_text(TARGETS["provider"])
    attacker_ds = expected_ds_text(TARGETS["attacker"])
    nameservers, published_ds, ds_signed = parent_state()

    if nameservers == [TARGETS["provider"].nameserver]:
        mode = "provider"
        expected = provider_ds
    elif nameservers == [TARGETS["attacker"].nameserver]:
        mode = "attacker"
        expected = attacker_ds
    else:
        mode = "unknown"
        expected = []

    rcode, ad, address = unbound_state()
    ds_matches = bool(expected) and published_ds == expected
    print(f"delegation: {mode}")
    print(f"parent NS: {', '.join(nameservers) if nameservers else '(none)'}")
    print(f"parent DS: {' | '.join(published_ds) if published_ds else '(none)'}")
    print(f"parent DS signed: {str(ds_signed).lower()}")
    print(f"parent DS matches active child: {str(ds_matches).lower()}")
    print(f"Unbound: rcode={rcode} ad={str(ad).lower()} address={address}")
    return 0 if mode != "unknown" and ds_signed and ds_matches else 1


def unauthorized_test() -> int:
    update = dns.update.Update(TLD_ZONE)
    # Adding the already-legitimate provider NS is harmless even if a server is
    # accidentally misconfigured, while still exercising UPDATE authorization.
    update.add("victim", TTL, dns.rdatatype.NS, TARGETS["provider"].nameserver)
    try:
        response = dns.query.tcp(update, TLD_SERVER, timeout=5)
    except dns.exception.DNSException as exc:
        raise RegistrarError(f"Unsigned UPDATE test failed unexpectedly: {exc}") from exc
    if response.rcode() == dns.rcode.NOERROR:
        raise RegistrarError("SECURITY FAILURE: the TLD accepted an unsigned DNS UPDATE")
    print(f"PASS: unsigned DNS UPDATE rejected with {dns.rcode.to_text(response.rcode())}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("status", "hijack", "restore", "unauthorized-test"),
        help="registrar action to perform",
    )
    args = parser.parse_args()

    if args.command == "status":
        return status()
    if args.command == "hijack":
        apply_target(TARGETS["attacker"])
        return 0
    if args.command == "restore":
        apply_target(TARGETS["provider"])
        return 0
    return unauthorized_test()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegistrarError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)

