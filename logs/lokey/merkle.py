"""Small Certificate-Transparency-style Merkle tree helpers.

Leaf hash: SHA256(0x00 || entry_bytes)
Node hash: SHA256(0x01 || left_hash || right_hash)
"""
from __future__ import annotations
import hashlib

def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()

def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()

def tree_hash(leaves: list[bytes]) -> bytes:
    """Return the Merkle root for already-hashed leaves."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return node_hash(tree_hash(leaves[:k]), tree_hash(leaves[k:]))

def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Return bottom-up sibling hashes for leaf at index."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    if len(leaves) == 1:
        return []
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [tree_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [tree_hash(leaves[:k])]

def verify_inclusion(entry: bytes, index: int, size: int,
                     proof: list[bytes], expected_root: bytes) -> bool:
    """Verify an inclusion path using the tree's recursive split rule."""
    if size <= 0 or index < 0 or index >= size:
        return False
    fn, sn = index, size - 1
    value = leaf_hash(entry)
    for sibling in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            value = node_hash(sibling, value)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            value = node_hash(value, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and value == expected_root
