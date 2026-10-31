import pytest

from lokey.merkle import leaf_hash, tree_hash
from lokey.consistency import (
    consistency_proof,
    verify_consistency,
)


def make_leaves(size):
    entries = [
        f"event-{i}".encode()
        for i in range(size)
    ]
    return [leaf_hash(entry) for entry in entries]


def test_consistency_proofs_for_different_sizes():
    for new_size in [2, 3, 5, 7, 8, 10, 15]:
        leaves = make_leaves(new_size)

        for old_size in range(1, new_size):
            old_root = tree_hash(leaves[:old_size])
            new_root = tree_hash(leaves)

            proof = consistency_proof(
                old_size,
                new_size,
                leaves,
            )

            assert verify_consistency(
                old_size,
                new_size,
                old_root,
                new_root,
                proof,
            ), f"Failed: {old_size} -> {new_size}"


def test_identical_tree_sizes():
    leaves = make_leaves(5)
    root = tree_hash(leaves)

    proof = consistency_proof(5, 5, leaves)

    assert proof == []

    assert verify_consistency(
        5, 5, root, root, proof
    )


def test_empty_old_tree():
    leaves = make_leaves(5)
    empty_root = tree_hash([])
    new_root = tree_hash(leaves)

    proof = consistency_proof(0, 5, leaves)

    assert proof == []

    assert verify_consistency(
        0, 5, empty_root, new_root, proof
    )


def test_reject_modified_proof():
    leaves = make_leaves(5)

    old_root = tree_hash(leaves[:3])
    new_root = tree_hash(leaves)

    proof = consistency_proof(3, 5, leaves)

    modified = proof.copy()
    modified[0] = leaf_hash(b"tampered")

    assert not verify_consistency(
        3, 5, old_root, new_root, modified
    )


def test_reject_wrong_old_root():
    leaves = make_leaves(5)

    new_root = tree_hash(leaves)
    wrong_old_root = tree_hash(make_leaves(2))

    proof = consistency_proof(3, 5, leaves)

    assert not verify_consistency(
        3, 5, wrong_old_root, new_root, proof
    )


def test_reject_wrong_tree_size():
    leaves = make_leaves(5)

    old_root = tree_hash(leaves[:3])
    new_root = tree_hash(leaves)

    proof = consistency_proof(3, 5, leaves)

    assert not verify_consistency(
        5, 3, new_root, old_root, proof
    )


def test_reject_insufficient_leaves():
    leaves = make_leaves(3)

    with pytest.raises(ValueError):
        consistency_proof(2, 5, leaves)


def test_reject_extra_proof_hash():
    leaves = make_leaves(5)

    old_root = tree_hash(leaves[:3])
    new_root = tree_hash(leaves)

    proof = consistency_proof(3, 5, leaves)
    proof.append(leaf_hash(b"extra"))

    assert not verify_consistency(
        3, 5, old_root, new_root, proof
    )
