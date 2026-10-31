
"""Append-only JSONL event store and signed tree-head support."""

from __future__ import annotations
from .consistency import consistency_proof

import json
import os
from pathlib import Path
from datetime import datetime, timezone

from .merkle import leaf_hash, tree_hash, inclusion_proof
from .signing import sign_payload, export_public_key

DATA_DIR = Path(os.getenv("LOKEY_DATA_DIR", "data"))
EVENTS_FILE = DATA_DIR / "events.jsonl"
TREE_HEADS_FILE = DATA_DIR / "tree_heads.jsonl"


def read_events() -> list[dict]:
    if not EVENTS_FILE.exists():
        return []

    events = []

    for line in EVENTS_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))

    return events


def append_event(event: dict) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    stored = dict(event)
    stored.setdefault(
        "observed_at",
        datetime.now(timezone.utc).isoformat()
    )

    encoded = json.dumps(
        stored,
        sort_keys=True,
        separators=(",", ":")
    )

    with EVENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(encoded + "\n")

    return stored


def _leaves(events: list[dict]) -> list[bytes]:
    return [
        leaf_hash(
            json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":")
            ).encode("utf-8")
        )
        for event in events
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
                separators=(",", ":")
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
        "event": events[index],
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