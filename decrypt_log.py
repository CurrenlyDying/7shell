"""Decrypt an audit log produced by logcrypt.audit_encrypt.

Usage:  python decrypt_log.py <private_key_file> [audit.log]

<private_key_file> holds the base64 X25519 private key you generated off the
box. Non-encrypted lines (plaintext fallback written before a key was installed)
pass through unchanged.
"""
import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"mcp-audit-log-v1"


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    priv = X25519PrivateKey.from_private_bytes(
        base64.b64decode(Path(sys.argv[1]).read_text().strip())
    )
    log = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).parent / "audit.log"
    for line in log.read_text().splitlines():
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[1] == "ENC":
            try:
                raw = base64.b64decode(parts[2])
                eph = X25519PublicKey.from_public_bytes(raw[:32])
                nonce, ct = raw[32:44], raw[44:]
                key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(priv.exchange(eph))
                detail = ChaCha20Poly1305(key).decrypt(nonce, ct, None).decode()
                print(parts[0] + " " + detail)
            except Exception as e:
                print(parts[0] + " <decrypt failed: " + e.__class__.__name__ + ">")
        else:
            print(line)


if __name__ == "__main__":
    main()
