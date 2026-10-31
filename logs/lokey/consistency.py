
"""Certificate Transparency-style Merkle consistency proofs."""

from __future__ import annotations

import hashlib

from lokey.merkle import node_hash, tree_hash


def _subproof(
    old_size: int,
    leaves: list[bytes],
    complete: bool,
) -> list[bytes]:
    """Recursively construct a consistency proof."""
    new_size = len(leaves)

    if old_size == new_size:
        return [] if complete else [tree_hash(leaves)]

    k = 1 << ((new_size - 1).bit_length() - 1)

    if old_size <= k:
        return (
            _subproof(old_size, leaves[:k], complete)
            + [tree_hash(leaves[k:])]
        )

    return (
        _subproof(old_size - k, leaves[k:], False)
        + [tree_hash(leaves[:k])]
    )


def consistency_proof(
    old_size: int,
    new_size: int,
    leaves: list[bytes],
) -> list[bytes]:
    """
    Generate a proof that the old tree is a prefix of the new tree.

    Leaves must already be hashed using leaf_hash().
    """
    if old_size < 0 or new_size < 0:
        raise ValueError("Tree sizes cannot be negative")

    if old_size > new_size:
        raise ValueError("Old tree cannot be larger than new tree")

    if new_size > len(leaves):
        raise ValueError("Not enough leaves for requested tree size")

    if old_size == 0 or old_size == new_size:
        return []

    return _subproof(old_size, leaves[:new_size], True)


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: list[bytes],
) -> bool:
    """
    Verify that a newer Merkle tree extends an older Merkle tree.
    """

    empty_root = hashlib.sha256(b"").digest()

    if old_size < 0 or new_size < 0:
        return False

    if old_size > new_size:
        return False

    if not isinstance(proof, list):
        return False

    if not isinstance(old_root, bytes) or not isinstance(new_root, bytes):
        return False

    if len(old_root) != 32 or len(new_root) != 32:
        return False

    if any(not isinstance(h, bytes) or len(h) != 32 for h in proof):
        return False

    # Empty old tree.
    if old_size == 0:
        return old_root == empty_root and len(proof) == 0

    # Identical tree sizes.
    if old_size == new_size:
        return old_root == new_root and len(proof) == 0

    if new_size == 0 or not proof:
        return False

    fn = old_size - 1
    sn = new_size - 1

    # Find the first node shared by both tree calculations.
    while fn & 1:
        fn >>= 1
        sn >>= 1

    proof_index = 0

    if fn == 0:
        first_root = old_root
        second_root = old_root
    else:
        first_root = proof[0]
        second_root = proof[0]
        proof_index = 1

    while proof_index < len(proof):
        if sn == 0:
            return False

        sibling = proof[proof_index]

        if (fn & 1) or fn == sn:
            first_root = node_hash(sibling, first_root)
            second_root = node_hash(sibling, second_root)

            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            second_root = node_hash(second_root, sibling)

        fn >>= 1
        sn >>= 1
        proof_index += 1

    return (
        sn == 0
        and first_root == old_root
        and second_root == new_root
    )
