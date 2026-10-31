"""Independent verification of historical LoKey signed tree heads."""

import json
import os
import sys
from pathlib import Path

from lokey.signing import verify_tree_head


DATA_DIR = Path(os.getenv("LOKEY_DATA_DIR", "data"))
TREE_HEADS_FILE = DATA_DIR / "tree_heads.jsonl"
PUBLIC_KEY_FILE = DATA_DIR / "log_ed25519_public.pem"


def main() -> int:
    print("LoKey - DNS Transparency Log Verification")
    print("=" * 45)

    # Check required files.
    if not PUBLIC_KEY_FILE.is_file():
        print(f"[ERROR] Public key not found: {PUBLIC_KEY_FILE}")
        return 1

    if not TREE_HEADS_FILE.is_file():
        print(f"[ERROR] Tree heads file not found: {TREE_HEADS_FILE}")
        return 1

    try:
        lines = TREE_HEADS_FILE.read_text(
            encoding="utf-8"
        ).splitlines()
    except (OSError, UnicodeError) as exc:
        print(f"[ERROR] Cannot read tree heads: {exc}")
        return 1

    valid = 0
    invalid = 0

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        try:
            tree_head = json.loads(line)

            if not isinstance(tree_head, dict):
                raise ValueError("Tree head must be a JSON object")

        except (json.JSONDecodeError, ValueError) as exc:
            print(f"[FAIL] Line {line_number}: Malformed JSON ({exc})")
            invalid += 1
            continue

        if verify_tree_head(tree_head, PUBLIC_KEY_FILE):
            print(
                f"[PASS] Tree head at line {line_number} "
                f"(tree size: {tree_head.get('tree_size', 'unknown')})"
            )
            valid += 1
        else:
            print(
                f"[FAIL] Tree head at line {line_number}: "
                "Signature verification failed"
            )
            invalid += 1

    print("=" * 45)
    print(f"Valid:   {valid}")
    print(f"Invalid: {invalid}")

    if valid + invalid == 0:
        print("[ERROR] No tree heads found.")
        return 1

    if invalid:
        print("Verification FAILED.")
        return 1

    print("All tree heads verified successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())