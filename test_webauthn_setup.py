#!/usr/bin/env python3
"""Standalone test of the WebAuthn setup signature-verification path, no
phone/Termux round trip needed. Runs the same functions the live
/webauthn/setup route calls: start_setup() -> sign -> 
verify_setup_signature_and_begin_registration(), using a throwaway SSH key
that is never the real signing key and is discarded when the script exits.

Does not modify data/allowed_signers on disk: only this process's own copy
of the ALLOWED_SIGNERS_PATH constant is repointed, in memory, for its own
lifetime. Leaves one harmless test row in webauthn_setup_sessions that
expires in 10 minutes like any real session.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import auth_provider
import webauthn_login


def run() -> bool:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        key_path = td / "test_key"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key_path), "-C", "test-harness"],
            check=True, capture_output=True,
        )
        keytype, b64 = key_path.with_suffix(".pub").read_text().split()[:2]
        signers_path = td / "allowed_signers"
        signers_path.write_text(f"{auth_provider.SIGNATURE_PRINCIPAL} {keytype} {b64}\n")

        auth_provider.ALLOWED_SIGNERS_PATH = signers_path
        provider = auth_provider.ShellAuthProvider(base_url="https://mcp.example.com")

        session_id, nonce = webauthn_login.start_setup()
        print(f"session_id = {session_id}")
        print(f"nonce      = {nonce}")

        nonce_path = td / "nonce.txt"
        nonce_path.write_text(nonce + "\n")
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_path),
             "-n", webauthn_login.SETUP_NAMESPACE, str(nonce_path)],
            check=True, capture_output=True,
        )
        sig_path = nonce_path.with_suffix(".txt.sig")
        signature = sig_path.read_text()

        options_json, error, _ = webauthn_login.verify_setup_signature_and_begin_registration(
            provider, "203.0.113.1", session_id, signature, rp_id="mcp.example.com",
        )
        if error:
            print(f"FAIL (correct-namespace signature): {error}")
            return False
        print(f"PASS: correct-namespace signature verified, {len(options_json)} bytes of registration options returned")

        sig_path.unlink()
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_path),
             "-n", auth_provider.SIGNATURE_NAMESPACE, str(nonce_path)],
            check=True, capture_output=True,
        )
        wrong_ns_sig = sig_path.read_text()
        wrongly_accepted = provider.verify_raw_signature(nonce, wrong_ns_sig, namespace=webauthn_login.SETUP_NAMESPACE)
        print(f"wrong-namespace signature accepted (must be False): {wrongly_accepted}")
        return not wrongly_accepted


if __name__ == "__main__":
    ok = run()
    print("RESULT:", "ALL PASS" if ok else "FAILURE DETECTED")
    sys.exit(0 if ok else 1)
