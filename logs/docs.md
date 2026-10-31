# LoKey Logs – Developer Reference

## Purpose

LoKey Logs is the logging component of a DNSSEC monitoring application. It receives DNS change events, stores them, and provides cryptographic evidence of event inclusion.

## Technology

- Python
- Flask
- SHA-256
- Ed25519
- JSON Lines
- Pytest

## Modules

### app.py
Provides the HTTP API and validates incoming events.

### lokey/store.py
Handles event persistence, event reading, tree-head generation, Ed25519 signing and inclusion-proof construction.

### lokey/merkle.py
Implements SHA-256 leaf hashing, internal-node hashing, Merkle root calculation, inclusion-proof generation and verification.

## Cryptographic design

Leaf:
`SHA256(0x00 || entry)`

Internal node:
`SHA256(0x01 || left_hash || right_hash)`

Tree head:
- Tree size
- Timestamp
- Merkle root hash
- Ed25519 signature

## API

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Health check |
| POST | /events | Append event |
| GET | /events | Read events |
| GET | /tree-head | Generate signed tree head |
| GET | /proof/{index} | Generate inclusion proof |

## Data flow

1. Collector detects DNS change.
2. Collector sends a JSON event to Flask.
3. Flask validates the event.
4. The event is appended to JSONL storage.
5. Events are hashed into a Merkle tree.
6. The tree root is signed with Ed25519.
7. Inclusion proofs can be generated and independently verified.

## Security considerations

- Protect the Ed25519 private key.
- Distribute and authenticate the public key.
- Preserve previously published tree heads.
- Implement consistency proofs.
- Do not treat local JSONL storage as inherently tamper-proof.
- Keep attack simulations restricted to the isolated .test lab.

## Remaining development work

1. Merkle consistency proofs.
2. Independent signature verification CLI.
3. Historical tree-head storage.
4. Webhook notifications.
5. Domain timeline interface.
6. Collector integration.