"""Generate an Ed25519 keypair for policy-bundle signing.

Usage::

    python scripts/gen_keys.py --out-dir ./keys
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sentinel.utils.crypto import generate_ed25519_keypair, public_key_to_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    private, public = generate_ed25519_keypair()

    priv_path = args.out_dir / "policy.key"
    pub_path = args.out_dir / "policy.pub"
    priv_path.write_bytes(
        private.private_bytes_raw()
        if hasattr(private, "private_bytes_raw")
        else private.private_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
            format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.Raw,
            encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
        )
    )
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(public_key_to_bytes(public))
    print(f"wrote {priv_path} (mode 0600)")
    print(f"wrote {pub_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
