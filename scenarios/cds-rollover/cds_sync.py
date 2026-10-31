#!/usr/bin/env python3
"""Strict CDS-to-parent-DS synchronizer for the isolated LoKey lab."""

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
import dns.rdata
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.tsigkeyring
import dns.update


ROOT_SERVER = "172.30.0.10"
TLD_SERVER = "172.30.0.11"
PROVIDER_SERVER = "172.30.0.12"
ROOT_ZONE = dns.name.from_text(".")
TLD_ZONE = dns.name.from_text("test.")
CHILD_ZONE = dns.name.from_text("victim.test.")
TSIG_NAME = "mock-registrar."
TTL = 30
SUPPORTED_ALGORITHMS = {13}  # ECDSAP256SHA256
SUPPORTED_DIGEST_TYPES = {2}  # SHA-256


class SyncError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChainState:
    child_keys: dns.rrset.RRset
    child_cds: dns.rrset.RRset
    parent_ds: dns.rrset.RRset
    tld_keys: dns.rrset.RRset
    parent_ns: tuple[str, ...]


def query(server: str, owner: dns.name.Name, rdtype: dns.rdatatype.RdataType) -> dns.message.Message:
    request = dns.message.make_query(owner, rdtype, want_dnssec=True)
    request.flags &= ~dns.flags.RD
    try:
        response = dns.query.udp(request, server, timeout=4)
    except dns.exception.DNSException as exc:
        raise SyncError(f"DNS query to {server} for {owner} {dns.rdatatype.to_text(rdtype)} failed: {exc}") from exc
    if response.rcode() != dns.rcode.NOERROR:
        raise SyncError(
            f"DNS query to {server} for {owner} {dns.rdatatype.to_text(rdtype)} returned "
            f"{dns.rcode.to_text(response.rcode())}"
        )
    return response


def rrset_from(response: dns.message.Message, owner: dns.name.Name, rdtype: dns.rdatatype.RdataType) -> dns.rrset.RRset:
    for section in (response.answer, response.authority):
        for rrset in section:
            if rrset.name == owner and rrset.rdtype == rdtype:
                return rrset
    raise SyncError(f"Missing {owner} {dns.rdatatype.to_text(rdtype)} RRset")


def signatures_from(
    response: dns.message.Message,
    owner: dns.name.Name,
    covered: dns.rdatatype.RdataType,
) -> dns.rrset.RRset:
    source = rrset_from(response, owner, dns.rdatatype.RRSIG)
    selected = dns.rrset.RRset(owner, dns.rdataclass.IN, dns.rdatatype.RRSIG)
    selected.ttl = source.ttl
    for signature in source:
        if signature.covers() == covered:
            selected.add(signature, source.ttl)
    if not selected:
        raise SyncError(f"Missing RRSIG({dns.rdatatype.to_text(covered)}) for {owner}")
    return selected


def read_root_anchor() -> dns.rrset.RRset:
    path = Path(os.environ.get("ROOT_TRUST_ANCHOR", "/trust-anchor/root.key"))
    try:
        lines = [line.strip() for line in path.read_text(encoding="ascii").splitlines()]
    except OSError as exc:
        raise SyncError(f"Could not read private-root trust anchor {path}: {exc}") from exc
    records = []
    ttl = 3600
    for line in lines:
        if not line or line.startswith(";"):
            continue
        fields = line.split()
        if len(fields) < 8 or fields[3].upper() != "DNSKEY":
            raise SyncError(f"Malformed private-root trust anchor in {path}")
        ttl = int(fields[1])
        records.append(" ".join(fields[4:]))
    if not records:
        raise SyncError(f"Private-root trust anchor {path} contains no DNSKEY")
    return dns.rrset.from_text_list(ROOT_ZONE, ttl, "IN", "DNSKEY", records)


def check_key(key, context: str) -> None:
    if key.protocol != 3 or key.algorithm not in SUPPORTED_ALGORITHMS:
        raise SyncError(f"Unsupported or malformed DNSKEY in {context}: {key.to_text()}")
    if (key.flags & 0x0101) != 0x0101:
        raise SyncError(f"DNSKEY is not an eligible SEP zone key in {context}: tag {dns.dnssec.key_id(key)}")


def check_ds(ds, context: str) -> None:
    if ds.key_tag == 0 and ds.algorithm == 0 and ds.digest_type == 0:
        raise SyncError("CDS deletion signaling (0 0 0 00) is deliberately unsupported")
    if ds.algorithm not in SUPPORTED_ALGORITHMS:
        raise SyncError(f"Unsupported DNSSEC algorithm {ds.algorithm} in {context}")
    if ds.digest_type not in SUPPORTED_DIGEST_TYPES:
        raise SyncError(f"Unsupported DS digest type {ds.digest_type} in {context}")


def ds_matches_key(owner: dns.name.Name, ds, key) -> bool:
    if ds.key_tag != dns.dnssec.key_id(key) or ds.algorithm != key.algorithm:
        return False
    calculated = dns.dnssec.make_ds(owner, key, ds.digest_type)
    return calculated.digest == ds.digest


def filtered_signatures(signatures: dns.rrset.RRset, trusted_tags: set[int]) -> dns.rrset.RRset:
    selected = dns.rrset.RRset(signatures.name, signatures.rdclass, signatures.rdtype)
    selected.ttl = signatures.ttl
    for signature in signatures:
        if signature.key_tag in trusted_tags:
            selected.add(signature, signatures.ttl)
    if not selected:
        raise SyncError(f"No DNSKEY signature was made by a currently trusted key: {sorted(trusted_tags)}")
    return selected


def authenticate_dnskeys(
    zone: dns.name.Name,
    keys: dns.rrset.RRset,
    signatures: dns.rrset.RRset,
    trust_ds: dns.rrset.RRset,
    context: str,
) -> None:
    for key in keys:
        if key.protocol != 3 or key.algorithm not in SUPPORTED_ALGORITHMS:
            raise SyncError(f"Unsupported or malformed DNSKEY in {context}: {key.to_text()}")
    trusted_tags: set[int] = set()
    for ds in trust_ds:
        check_ds(ds, context)
        matches = [key for key in keys if ds_matches_key(zone, ds, key)]
        if not matches:
            raise SyncError(f"Trusted DS tag {ds.key_tag} does not match any published {context} DNSKEY")
        trusted_tags.add(ds.key_tag)
    try:
        dns.dnssec.validate(keys, filtered_signatures(signatures, trusted_tags), {zone: keys})
    except (dns.dnssec.ValidationFailure, dns.exception.DNSException, ValueError) as exc:
        raise SyncError(f"Could not authenticate the {context} DNSKEY RRset: {exc}") from exc


def authenticate_root() -> dns.rrset.RRset:
    anchor = read_root_anchor()
    response = query(ROOT_SERVER, ROOT_ZONE, dns.rdatatype.DNSKEY)
    keys = rrset_from(response, ROOT_ZONE, dns.rdatatype.DNSKEY)
    signatures = signatures_from(response, ROOT_ZONE, dns.rdatatype.DNSKEY)
    anchor_tags = {dns.dnssec.key_id(key) for key in anchor}
    for key in anchor:
        if key not in keys:
            raise SyncError("The live private-root DNSKEY RRset does not contain the persisted trust anchor")
    try:
        dns.dnssec.validate(keys, filtered_signatures(signatures, anchor_tags), {ROOT_ZONE: keys})
    except (dns.dnssec.ValidationFailure, dns.exception.DNSException, ValueError) as exc:
        raise SyncError(f"Could not authenticate the private-root DNSKEY RRset: {exc}") from exc
    return keys


def validate_rrset(rrset: dns.rrset.RRset, signatures: dns.rrset.RRset, keys: dns.rrset.RRset, zone: dns.name.Name, label: str) -> None:
    try:
        dns.dnssec.validate(rrset, signatures, {zone: keys})
    except (dns.dnssec.ValidationFailure, dns.exception.DNSException, ValueError) as exc:
        raise SyncError(f"Invalid {label} signature: {exc}") from exc


def validate_chain(cds_override: dns.rrset.RRset | None = None) -> ChainState:
    root_keys = authenticate_root()

    root_ds_response = query(ROOT_SERVER, TLD_ZONE, dns.rdatatype.DS)
    root_ds = rrset_from(root_ds_response, TLD_ZONE, dns.rdatatype.DS)
    validate_rrset(
        root_ds,
        signatures_from(root_ds_response, TLD_ZONE, dns.rdatatype.DS),
        root_keys,
        ROOT_ZONE,
        "root-to-test DS",
    )

    tld_key_response = query(TLD_SERVER, TLD_ZONE, dns.rdatatype.DNSKEY)
    tld_keys = rrset_from(tld_key_response, TLD_ZONE, dns.rdatatype.DNSKEY)
    authenticate_dnskeys(
        TLD_ZONE,
        tld_keys,
        signatures_from(tld_key_response, TLD_ZONE, dns.rdatatype.DNSKEY),
        root_ds,
        "test.",
    )

    parent_ds_response = query(TLD_SERVER, CHILD_ZONE, dns.rdatatype.DS)
    parent_ds = rrset_from(parent_ds_response, CHILD_ZONE, dns.rdatatype.DS)
    validate_rrset(
        parent_ds,
        signatures_from(parent_ds_response, CHILD_ZONE, dns.rdatatype.DS),
        tld_keys,
        TLD_ZONE,
        "test-to-victim DS",
    )

    child_key_response = query(PROVIDER_SERVER, CHILD_ZONE, dns.rdatatype.DNSKEY)
    child_keys = rrset_from(child_key_response, CHILD_ZONE, dns.rdatatype.DNSKEY)
    authenticate_dnskeys(
        CHILD_ZONE,
        child_keys,
        signatures_from(child_key_response, CHILD_ZONE, dns.rdatatype.DNSKEY),
        parent_ds,
        "victim.test.",
    )

    cds_response = query(PROVIDER_SERVER, CHILD_ZONE, dns.rdatatype.CDS)
    child_cds = cds_override if cds_override is not None else rrset_from(cds_response, CHILD_ZONE, dns.rdatatype.CDS)
    cds_signatures = signatures_from(cds_response, CHILD_ZONE, dns.rdatatype.CDS)
    validate_rrset(child_cds, cds_signatures, child_keys, CHILD_ZONE, "child CDS")

    for cds in child_cds:
        check_ds(cds, "child CDS")
        matches = [key for key in child_keys if ds_matches_key(CHILD_ZONE, cds, key)]
        if not matches:
            raise SyncError(f"CDS tag {cds.key_tag} does not match a published DNSKEY")
        for key in matches:
            check_key(key, "child CDS")

    ns_response = query(TLD_SERVER, CHILD_ZONE, dns.rdatatype.NS)
    parent_ns = tuple(sorted(item.target.to_text() for item in rrset_from(ns_response, CHILD_ZONE, dns.rdatatype.NS)))
    if parent_ns != ("ns.victim.test.",):
        raise SyncError(f"Parent delegation is not the legitimate provider NS: {parent_ns}")
    return ChainState(child_keys, child_cds, parent_ds, tld_keys, parent_ns)


def tags(rrset: dns.rrset.RRset) -> list[int]:
    return sorted(item.key_tag for item in rrset)


def parse_tsig_secret() -> str:
    path = Path(os.environ.get("TSIG_KEY_FILE", "/run/secrets/registrar.key"))
    try:
        contents = path.read_text(encoding="ascii")
    except OSError as exc:
        raise SyncError(f"Could not read TSIG key file {path}: {exc}") from exc
    match = re.search(r'\bsecret\s+"([^"]+)"\s*;', contents)
    if not match:
        raise SyncError(f"No BIND-style secret was found in {path}")
    return match.group(1)


def update_parent(cds_rrset: dns.rrset.RRset) -> None:
    keyring = dns.tsigkeyring.from_text({TSIG_NAME: parse_tsig_secret()})
    update = dns.update.Update(
        TLD_ZONE,
        keyring=keyring,
        keyname=TSIG_NAME,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    update.delete("victim", dns.rdatatype.DS)
    for cds in cds_rrset:
        update.add("victim", TTL, dns.rdatatype.DS, cds.to_text())
    try:
        response = dns.query.tcp(update, TLD_SERVER, timeout=5)
    except dns.exception.DNSException as exc:
        raise SyncError(f"TSIG parent update failed: {exc}") from exc
    if response.rcode() != dns.rcode.NOERROR:
        raise SyncError(f"TLD rejected the TSIG update: {dns.rcode.to_text(response.rcode())}")


def wait_for_expected_parent(expected_text: set[str], original_ns: tuple[str, ...]) -> None:
    for _ in range(60):
        try:
            state = validate_chain()
        except SyncError:
            time.sleep(0.5)
            continue
        current = {item.to_text() for item in state.parent_ds}
        if current == expected_text and state.parent_ns == original_ns:
            return
        time.sleep(0.5)
    raise SyncError("Timed out waiting for the expected signed parent DS RRset")


def sync() -> int:
    state = validate_chain()
    previous = tags(state.parent_ds)
    proposed = tags(state.child_cds)
    print(f"previous_ds_tags={','.join(map(str, previous))}")
    print(f"proposed_ds_tags={','.join(map(str, proposed))}")
    print("validation=complete-private-chain-and-signed-cds")
    current_text = {item.to_text() for item in state.parent_ds}
    proposed_text = {item.to_text() for item in state.child_cds}
    if current_text == proposed_text:
        print("action=noop")
        return 0
    update_parent(state.child_cds)
    wait_for_expected_parent(proposed_text, state.parent_ns)
    print("action=updated-parent-ds-via-tsig")
    print("verification=expected-signed-parent-ds-published")
    return 0


def validate_only() -> int:
    state = validate_chain()
    print(f"previous_ds_tags={','.join(map(str, tags(state.parent_ds)))}")
    print(f"proposed_ds_tags={','.join(map(str, tags(state.child_cds)))}")
    print("validation=complete-private-chain-and-signed-cds")
    print("action=validation-only")
    return 0


def tampered_test() -> int:
    live_response = query(PROVIDER_SERVER, CHILD_ZONE, dns.rdatatype.CDS)
    live = rrset_from(live_response, CHILD_ZONE, dns.rdatatype.CDS)
    if not live:
        raise SyncError("Cannot run tamper test without a live CDS RRset")
    tampered = dns.rrset.RRset(CHILD_ZONE, dns.rdataclass.IN, dns.rdatatype.CDS)
    tampered.ttl = live.ttl
    for index, item in enumerate(live):
        text = item.to_text()
        if index == 0:
            fields = text.split()
            digest = fields[3]
            fields[3] = digest[:-1] + ("0" if digest[-1].upper() != "0" else "1")
            text = " ".join(fields)
        tampered.add(dns.rdata.from_text("IN", "CDS", text), live.ttl)
    try:
        validate_chain(cds_override=tampered)
    except SyncError as exc:
        print(f"action=rejected-tampered-cds-before-update")
        print(f"validation=expected-failure: {exc}")
        return 0
    raise SyncError("SECURITY FAILURE: tampered CDS unexpectedly passed cryptographic validation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("sync", "validate", "verify-tampered"), nargs="?", default="sync")
    args = parser.parse_args()
    if args.command == "sync":
        return sync()
    return validate_only() if args.command == "validate" else tampered_test()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SyncError, dns.exception.DNSException, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
