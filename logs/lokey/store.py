"""Append-only observation store and signed Merkle tree-head support."""

from __future__ import annotations

import json
import os
from pathlib import Path
from datetime import datetime, timezone

from .merkle import leaf_hash, tree_hash, inclusion_proof
from .consistency import consistency_proof
from .signing import sign_payload, export_public_key


DATA_DIR = Path(os.getenv("LOKEY_DATA_DIR", "data"))
EVENTS_FILE = DATA_DIR / "events.jsonl"
ASSESSMENTS_FILE = DATA_DIR / "assessments.jsonl"
TREE_HEADS_FILE = DATA_DIR / "tree_heads.jsonl"


def canonical_observation(observation: dict) -> bytes:
    """Serialize an observation using the contract's exact format."""
    return json.dumps(
        observation,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def read_events() -> list[dict]:
    """Read immutable observations."""
    if not EVENTS_FILE.exists():
        return []

    return [
        json.loads(line)
        for line in EVENTS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def read_assessments() -> list[dict]:
    """Read separately stored assessments."""
    if not ASSESSMENTS_FILE.exists():
        return []

    return [
        json.loads(line)
        for line in ASSESSMENTS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def append_event(event: dict) -> dict:
    """Append an observation and its separate assessment."""
    observation = event["observation"]
    assessment = event["assessment"]

    # The next zero-based Merkle leaf index.
    event_index = len(read_events())

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    encoded = canonical_observation(observation)
    digest = leaf_hash(encoded).hex()

    stored_assessment = {
        "leaf_hash": digest,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "assessment": assessment,
    }

    # Append the immutable observation.
    with EVENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(encoded.decode("utf-8") + "\n")

    # Store the assessment separately, linked by observation hash.
    with ASSESSMENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                stored_assessment,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ) + "\n"
        )

    return {
        "index": event_index,
        "observation": observation,
        "leaf_hash": digest,
        "assessment": assessment,
    }


def _leaves(events: list[dict]) -> list[bytes]:
    return [
        leaf_hash(canonical_observation(observation))
        for observation in events
    ]


def signed_tree_head() -> dict:
    events = read_events()
    root = tree_hash(_leaves(events))

    payload = {
        "tree_size": len(events),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "root_hash": root.hex(),
    }

    export_public_key()

    tree_head = {
        **payload,
        "signature": sign_payload(payload),
    }

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with TREE_HEADS_FILE.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                tree_head,
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
        )

    return tree_head


def read_tree_heads() -> list[dict]:
    if not TREE_HEADS_FILE.exists():
        return []

    return [
        json.loads(line)
        for line in TREE_HEADS_FILE.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


def proof_for(index: int) -> dict:
    events = read_events()
    leaves = _leaves(events)

    if not 0 <= index < len(events):
        raise IndexError("event index out of range")

    return {
        "index": index,
        "tree_size": len(events),
        "observation": events[index],
        "audit_path": [
            h.hex() for h in inclusion_proof(leaves, index)
        ],
        "root_hash": tree_hash(leaves).hex(),
    }


def consistency_proof_for(old_size: int) -> dict:
    """Build a proof that the current tree extends an older tree."""
    events = read_events()
    leaves = _leaves(events)

    new_size = len(leaves)

    if old_size < 0 or old_size > new_size:
        raise ValueError("Invalid old tree size")

    old_root = tree_hash(leaves[:old_size])
    new_root = tree_hash(leaves)

    proof = consistency_proof(old_size, new_size, leaves)

    return {
        "old_tree_size": old_size,
        "new_tree_size": new_size,
        "old_root_hash": old_root.hex(),
        "new_root_hash": new_root.hex(),
        "consistency_path": [h.hex() for h in proof],
    }
