from lokey.merkle import leaf_hash, tree_hash, inclusion_proof, verify_inclusion

def test_inclusion_proofs_for_small_tree():
    entries = [f"event-{i}".encode() for i in range(7)]
    leaves = [leaf_hash(e) for e in entries]
    root = tree_hash(leaves)
    for i, entry in enumerate(entries):
        proof = inclusion_proof(leaves, i)
        assert verify_inclusion(entry, i, len(entries), proof, root)


def test_inclusion_proofs_for_odd_tree_sizes():
    for size in [1, 2, 3, 5, 7, 8, 10]:
        entries = [
            f"event-{i}".encode()
            for i in range(size)
        ]

        leaves = [leaf_hash(e) for e in entries]
        root = tree_hash(leaves)

        for index, entry in enumerate(entries):
            proof = inclusion_proof(leaves, index)

            assert verify_inclusion(
                entry,
                index,
                size,
                proof,
                root,
            )


def test_inclusion_proof_rejects_wrong_entry():
    entries = [b"event-0", b"event-1", b"event-2"]
    leaves = [leaf_hash(e) for e in entries]

    proof = inclusion_proof(leaves, 1)
    root = tree_hash(leaves)

    assert not verify_inclusion(
        b"fake-event",
        1,
        3,
        proof,
        root,
    )