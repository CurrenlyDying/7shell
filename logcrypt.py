"""Write-only audit logging.

Each log line's detail is encrypted to an X25519 public key whose private half
lives OFF this box. The server can append entries but cannot read them back;
only the holder of the offline private key can decrypt (see decrypt_log.py).

If no recipient key is installed at data/log_recipient.pub, audit_encrypt()
returns the line unchanged so events are never silently dropped (the file is
still 0600). Drop a key in later and new lines become encrypted with no restart.
"""
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RECIPIENT_PATH = Path(__file__).parent / "data" / "log_recipient.pub"
_INFO = b"mcp-audit-log-v1"


def _load_recipient():
    try:
        raw = base64.b64decode(RECIPIENT_PATH.read_text().strip())
    except (OSError, ValueError):
        return None
    if len(raw) != 32:
        return None
    try:
        return X25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def key_available() -> bool:
    """True if a usable recipient key is installed. Lets the server refuse to
    start when the operator requires encrypted audit lines, instead of silently
    falling back to plaintext."""
    return _load_recipient() is not None


def audit_encrypt(line: str) -> str:
    """Return 'ENC <base64>' encrypting line to the recipient key, or the line
    unchanged if no recipient key is installed."""
    recipient = _load_recipient()
    if recipient is None:
        return line
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(recipient)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(shared)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, line.encode(), None)
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ENC " + base64.b64encode(eph_pub + nonce + ct).decode()
