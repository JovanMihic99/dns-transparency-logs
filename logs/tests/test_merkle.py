from lokey.merkle import leaf_hash, tree_hash, inclusion_proof, verify_inclusion

def test_inclusion_proofs_for_small_tree():
    entries = [f"event-{i}".encode() for i in range(7)]
    leaves = [leaf_hash(e) for e in entries]
    root = tree_hash(leaves)
    for i, entry in enumerate(entries):
        proof = inclusion_proof(leaves, i)
        assert verify_inclusion(entry, i, len(entries), proof, root)
