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


class AuditKeyUnavailable(RuntimeError):
    """Raised by audit_encrypt(require=True) when no usable recipient key exists."""


def key_available() -> bool:
    """True if a usable recipient key is installed. Suitable for a startup check
    only: anything that must not write plaintext has to pass require=True to
    audit_encrypt instead, so the decision and the encryption see the same key."""
    return _load_recipient() is not None


def audit_encrypt(line: str, require: bool = False) -> str:
    """Return 'ENC <base64>' encrypting line to the recipient key.

    With require=False, a missing key means the line is returned unchanged, so
    events are never silently dropped. With require=True a missing key raises.

    The key is loaded exactly once here. Checking availability separately and
    then calling this would read the file twice, and a key removed between the
    two reads would pass the check and then be written in plaintext anyway.
    """
    recipient = _load_recipient()
    if recipient is None:
        if require:
            raise AuditKeyUnavailable(
                "audit encryption is required but data/log_recipient.pub is missing or invalid"
            )
        return line
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(recipient)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(shared)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, line.encode(), None)
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ENC " + base64.b64encode(eph_pub + nonce + ct).decode()
