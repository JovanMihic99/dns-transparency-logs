"""Ed25519 signing and independent signature verification."""

import json
from pathlib import Path
import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DATA_DIR = Path(os.getenv("LOKEY_DATA_DIR", "data"))
PRIVATE_KEY_FILE = DATA_DIR / "log_ed25519_private.pem"
PUBLIC_KEY_FILE = DATA_DIR / "log_ed25519_public.pem"


def canonical_json(payload: dict) -> bytes:
    """Serialize JSON deterministically."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_or_create_private_key() -> Ed25519PrivateKey:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_FILE.exists():
        key = serialization.load_pem_private_key(
            PRIVATE_KEY_FILE.read_bytes(),
            password=None,
        )
        PRIVATE_KEY_FILE.chmod(0o600)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("Stored private key is not an Ed25519 key")

        return key
    

    key = Ed25519PrivateKey.generate()

    PRIVATE_KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    PRIVATE_KEY_FILE.chmod(0o600)

    return key


def export_public_key() -> Path:
    """Export the public key corresponding to the log's private key."""
    private_key = load_or_create_private_key()
    public_key = private_key.public_key()

    PUBLIC_KEY_FILE.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    PUBLIC_KEY_FILE.chmod(0o644)

    return PUBLIC_KEY_FILE


def sign_payload(payload: dict) -> str:
    """Sign a dictionary and return its signature as hexadecimal."""
    private_key = load_or_create_private_key()
    return private_key.sign(canonical_json(payload)).hex()


def verify_payload(payload: dict, signature_hex: str,
                   public_key_path: Path = PUBLIC_KEY_FILE) -> bool:
    """Verify a signature using only the public key."""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_path.read_bytes()
        )

        if not isinstance(public_key, Ed25519PublicKey):
            return False

        signature = bytes.fromhex(signature_hex)

        public_key.verify(
            signature,
            canonical_json(payload),
        )

        return True

    except (InvalidSignature, ValueError, OSError, TypeError):
        return False


def verify_tree_head(tree_head: dict,
                     public_key_path: Path = PUBLIC_KEY_FILE) -> bool:
    """Verify a complete signed tree head."""
    payload = dict(tree_head)
    signature = payload.pop("signature", None)

    if not isinstance(signature, str):
        return False

    return verify_payload(payload, signature, public_key_path)