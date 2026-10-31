"""Append-only JSONL event store and signed tree-head support."""
from __future__ import annotations
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from .merkle import leaf_hash, tree_hash, inclusion_proof

DATA_DIR = Path(os.getenv("LOKEY_DATA_DIR", "data"))
EVENTS_FILE = DATA_DIR / "events.jsonl"
PRIVATE_KEY_FILE = DATA_DIR / "log_ed25519_private.pem"

def _load_or_create_key():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_FILE.exists():
        return serialization.load_pem_private_key(
            PRIVATE_KEY_FILE.read_bytes(), password=None
        )
    key = Ed25519PrivateKey.generate()
    PRIVATE_KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    try:
        PRIVATE_KEY_FILE.chmod(0o600)
    except OSError:
        pass
    return key

def read_events() -> list[dict]:
    if not EVENTS_FILE.exists():
        return []
    events = []
    for line in EVENTS_FILE.read_text().splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events

def append_event(event: dict) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    stored = dict(event)
    stored.setdefault("observed_at", datetime.now(timezone.utc).isoformat())
    # Canonical serialization makes the bytes being hashed deterministic.
    encoded = json.dumps(stored, sort_keys=True, separators=(",", ":"))
    with EVENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(encoded + "\n")
    return stored

def _leaves(events: list[dict]) -> list[bytes]:
    return [leaf_hash(json.dumps(e, sort_keys=True, separators=(",", ":")).encode())
            for e in events]

def signed_tree_head() -> dict:
    events = read_events()
    root = tree_hash(_leaves(events))
    payload = {
        "tree_size": len(events),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "root_hash": root.hex(),
    }
    signature = _load_or_create_key().sign(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    payload["signature"] = signature.hex()
    return payload

def proof_for(index: int) -> dict:
    events = read_events()
    leaves = _leaves(events)
    if not 0 <= index < len(events):
        raise IndexError("event index out of range")
    return {
        "index": index,
        "tree_size": len(events),
        "event": events[index],
        "audit_path": [h.hex() for h in inclusion_proof(leaves, index)],
        "root_hash": tree_hash(leaves).hex(),
    }
