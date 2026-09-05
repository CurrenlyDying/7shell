"""Passkey (WebAuthn) support, layered on top of the existing SSH-signature login.

Two independent ceremonies, both funnelling into ShellAuthProvider.complete_login()
on success, same as a verified SSH signature would:

  - setup (/webauthn/setup): prove you hold the SSH key, in a namespace distinct
    from ordinary login so a login signature can never double as a setup
    signature, then register a WebAuthn credential (a platform passkey, e.g. a
    phone's fingerprint reader). The SSH key stays the root of trust: only it
    can onboard a new passkey, a passkey alone can never onboard another one.

  - authenticate (/webauthn/authenticate/*): for an in-flight OAuth login
    session, verify a WebAuthn assertion against a previously registered
    credential.

Purely additive: with no credential ever registered, none of this changes
behavior, and SSH-signature login keeps working exactly as before.
"""
import json
import os
import secrets
import sqlite3
import time

import webauthn
from webauthn.helpers import exceptions
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from auth_provider import ShellAuthProvider, _connect, _lock

SETUP_NAMESPACE = "mcp-webauthn-setup"
SETUP_SESSION_TTL_SECONDS = 10 * 60
RP_NAME = "mcp-shell-server"
WEBAUTHN_USER_ID = os.environ.get("MCP_WEBAUTHN_USER_ID", "mcp-user").encode()
WEBAUTHN_USER_NAME = os.environ.get("MCP_WEBAUTHN_USER_NAME", "mcp-user")


def _init_tables() -> None:
    with _lock, _connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS webauthn_credentials (
            credential_id TEXT PRIMARY KEY,
            public_key BLOB NOT NULL,
            sign_count INTEGER NOT NULL,
            created_at REAL NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS webauthn_setup_sessions (
            session_id TEXT PRIMARY KEY,
            nonce TEXT NOT NULL,
            reg_challenge BLOB,
            expires_at REAL NOT NULL
        )""")
        try:
            conn.execute("ALTER TABLE login_sessions ADD COLUMN webauthn_challenge BLOB")
        except sqlite3.OperationalError:
            pass  # column already added by a previous run


_init_tables()


def has_credential() -> bool:
    with _connect() as conn:
        return conn.execute("SELECT 1 FROM webauthn_credentials LIMIT 1").fetchone() is not None


def start_setup() -> tuple[str, str]:
    """Create a new setup session, return (session_id, nonce) for the human to sign."""
    session_id = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO webauthn_setup_sessions (session_id, nonce, expires_at) VALUES (?, ?, ?)",
            (session_id, nonce, time.time() + SETUP_SESSION_TTL_SECONDS),
        )
    return session_id, nonce


def _get_setup_session(session_id: str) -> sqlite3.Row | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM webauthn_setup_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    if row is None or row["expires_at"] < time.time():
        return None
    return row


def verify_setup_signature_and_begin_registration(
    provider: ShellAuthProvider, ip: str, session_id: str, signature_text: str, rp_id: str
) -> tuple[str | None, str | None, str | None]:
    """Step 1+2 combined: verify the SSH signature over this setup session's nonce
    in the dedicated setup namespace, then generate WebAuthn registration options.
    Returns (options_json, error, nonce). Exactly one of options_json/error is set
    when the session itself is valid; nonce is returned either way so the caller
    can re-render a retry form without a second lookup."""
    row = _get_setup_session(session_id)
    if row is None:
        return None, "Setup link expired or invalid.", None
    nonce = row["nonce"]
    if provider.is_blocked(ip):
        return None, "Too many attempts. Try again later.", nonce
    if not provider.verify_raw_signature(nonce, signature_text, namespace=SETUP_NAMESPACE):
        provider.record_failed_attempt(ip)
        return None, "Signature did not verify.", nonce

    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=WEBAUTHN_USER_ID,
        user_name=WEBAUTHN_USER_NAME,
        user_display_name=WEBAUTHN_USER_NAME,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE webauthn_setup_sessions SET reg_challenge = ? WHERE session_id = ?",
            (options.challenge, session_id),
        )
    return webauthn.options_to_json(options), None, nonce


def complete_registration(
    session_id: str, credential: dict, rp_id: str, origin: str
) -> tuple[bool, str]:
    """Returns (ok, reason). reason is a short code the route turns into a
    human sentence: "ok", "session_gone" (code already used or expired),
    "verification_failed"."""
    row = _get_setup_session(session_id)
    if row is None or row["reg_challenge"] is None:
        return False, "session_gone"
    try:
        verified = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=bytes(row["reg_challenge"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except exceptions.WebAuthnException:
        return False, "verification_failed"

    credential_id = webauthn.helpers.bytes_to_base64url(verified.credential_id)
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO webauthn_credentials "
            "(credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, ?)",
            (credential_id, verified.credential_public_key, verified.sign_count, time.time()),
        )
        conn.execute("DELETE FROM webauthn_setup_sessions WHERE session_id = ?", (session_id,))
    return True, "ok"


def begin_authentication(provider: ShellAuthProvider, session_id: str, rp_id: str) -> str | None:
    """For an in-flight OAuth login_sessions row, generate a WebAuthn authentication
    challenge with no allow_credentials list, so the browser/OS can surface any
    resident passkey registered for this site. Returns options JSON, or None if
    the login session is missing or expired."""
    row = provider.get_login_session(session_id)
    if row is None:
        return None
    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE login_sessions SET webauthn_challenge = ? WHERE session_id = ?",
            (options.challenge, session_id),
        )
    return webauthn.options_to_json(options)


def verify_authentication(
    provider: ShellAuthProvider, ip: str, session_id: str, credential: dict, rp_id: str, origin: str
) -> bool:
    if provider.is_blocked(ip):
        return False
    row = provider.get_login_session(session_id)
    if row is None or row["webauthn_challenge"] is None:
        return False
    credential_id = credential.get("id") if isinstance(credential, dict) else None
    if not isinstance(credential_id, str):
        return False

    with _connect() as conn:
        cred = conn.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()
    if cred is None:
        provider.record_failed_attempt(ip)
        return False

    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=bytes(row["webauthn_challenge"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=bytes(cred["public_key"]),
            credential_current_sign_count=cred["sign_count"],
            require_user_verification=True,
        )
    except exceptions.WebAuthnException:
        provider.record_failed_attempt(ip)
        return False

    with _lock, _connect() as conn:
        conn.execute(
            "UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?",
            (verified.new_sign_count, credential_id),
        )
    return True


# ---- presentation (HTML/JS) ----

_STYLE = """<style>
body { font-family: system-ui, sans-serif; background: #111; color: #eee; display: flex;
       align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 2rem 0; }
form, .box { background: #1c1c1c; padding: 2rem; border-radius: 8px; width: 520px; max-width: 90vw;
        box-sizing: border-box; }
code, pre { background: #2a2a2a; border: 1px solid #444; border-radius: 4px; padding: 0.15rem 0.4rem; }
pre { padding: 0.8rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
textarea { width: 100%; padding: 0.6rem; margin-top: 0.5rem; margin-bottom: 1rem; box-sizing: border-box;
            background: #2a2a2a; border: 1px solid #444; color: #eee; border-radius: 4px;
            font-family: ui-monospace, monospace; font-size: 0.8rem; height: 8rem; }
button { width: 100%; padding: 0.6rem; background: #4a4af0; color: white; border: none; border-radius: 4px;
          cursor: pointer; }
.error { color: #ff6b6b; margin-bottom: 1rem; }
ol { padding-left: 1.2rem; }
li { margin-bottom: 0.6rem; }
#status { display: none; margin-top: 1rem; padding: 0.8rem; border-radius: 4px;
          font-size: 0.95rem; line-height: 1.45; }
#status.busy { background: #2a2a2a; border: 1px solid #555; color: #ddd; }
#status.ok { background: #14331f; border: 1px solid #2f7d4f; color: #7ee2a8; }
#status.err { background: #3a1a1a; border: 1px solid #8a3a3a; color: #ff9b9b; }
button:disabled { opacity: 0.55; cursor: default; }
.verified { color: #7ee2a8; }
</style>"""


def message_page_html(message: str) -> str:
    return f"""<!doctype html>
<html><head><title>{RP_NAME}</title>{_STYLE}</head>
<body><div class="box"><h2>{message}</h2></div></body></html>"""


def login_button_html(session_id: str) -> str:
    """The passkey button shown at the top of /login, only when a credential
    already exists (otherwise there is nothing for the browser to offer)."""
    if not has_credential():
        return ""
    return f"""
<div style="margin-bottom:1.2rem;padding-bottom:1.2rem;border-bottom:1px solid #444">
  <button type="button" id="wa-button" onclick="signInWithPasskey()"
          style="background:#2e8b57">Sign in with passkey</button>
  <p id="wa-status" style="color:#aaa;font-size:0.85rem;margin:0.5rem 0 0"></p>
</div>
<script>
async function signInWithPasskey() {{
  const statusEl = document.getElementById('wa-status');
  if (!(window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON)) {{
    statusEl.textContent = 'This browser does not support passkeys. Use the SSH signature below.';
    return;
  }}
  try {{
    const beginResp = await fetch('/webauthn/authenticate/begin', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{session: {session_id!r}}}),
    }});
    if (!beginResp.ok) {{ statusEl.textContent = 'Could not start passkey sign-in.'; return; }}
    const requestOptions = PublicKeyCredential.parseRequestOptionsFromJSON(await beginResp.json());
    const cred = await navigator.credentials.get({{ publicKey: requestOptions }});
    const completeResp = await fetch('/webauthn/authenticate/complete', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{session: {session_id!r}, credential: cred.toJSON()}}),
    }});
    const data = await completeResp.json();
    if (completeResp.ok) {{ window.location = data.redirect; }}
    else {{ statusEl.textContent = data.error || 'Passkey sign-in failed.'; }}
  }} catch (e) {{
    statusEl.textContent = e.name === 'NotAllowedError' ? 'Cancelled.' : ('Error: ' + e.message);
  }}
}}
</script>"""


def setup_form_html(session_id: str, nonce: str, error: str = "") -> str:
    error_html = f'<div class="error">{error}</div>' if error else ""
    return f"""<!doctype html>
<html><head><title>Register a passkey</title>{_STYLE}</head>
<body>
<form method="post" action="/webauthn/setup">
  <h2>Register a passkey</h2>
  {error_html}
  <input type="hidden" name="session" value="{session_id}">
  <p>This proves you hold the SSH key before letting you add a device-bound
  passkey (fingerprint, Face ID, security key) as an additional way to sign in.</p>
  <p>Challenge code (tap to select):</p>
  <input readonly value="{nonce}" onclick="this.select()"
         style="width:100%;box-sizing:border-box;font-family:monospace;padding:6px">
  <ol>
    <li>Run this locally (adjust the key path if needed):<pre>printf '%s\\n' '{nonce}' &gt; ~/mcp-nonce.txt
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n {SETUP_NAMESPACE} ~/mcp-nonce.txt
cat ~/mcp-nonce.txt.sig</pre></li>
    <li>Paste the resulting <code>-----BEGIN SSH SIGNATURE-----</code> block below.</li>
  </ol>
  <textarea name="signature" placeholder="-----BEGIN SSH SIGNATURE-----&#10;...&#10;-----END SSH SIGNATURE-----" autofocus></textarea>
  <button type="submit">Verify</button>
</form>
</body></html>"""


_REGISTER_PAGE = """<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register a passkey</title>__STYLE__</head>
<body>
<div class="box">
  <h2>Register this device</h2>
  <p class="verified">Signature verified. One step left.</p>
  <p>Tapping the button asks your phone for your fingerprint <b>once</b>, then
  stores a passkey on this device. You only do this a single time.</p>
  <button type="button" id="reg-button">Register this device</button>
  <div id="status"></div>
  <p id="restart" style="display:none;margin-top:1rem">
    <a href="/webauthn/setup" style="color:#8ab4f8">Start over with a new code</a></p>
</div>
<script>
const OPTIONS = __OPTIONS__;
const SESSION = __SESSION__;
let inFlight = false, done = false;
const btn = document.getElementById('reg-button');
const statusEl = document.getElementById('status');
function show(cls, text) {
  statusEl.className = cls; statusEl.textContent = text; statusEl.style.display = 'block';
}
function offerRestart() {
  btn.style.display = 'none';
  document.getElementById('restart').style.display = 'block';
}
btn.addEventListener('click', async function () {
  if (inFlight || done) return;
  if (!(window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON)) {
    show('err', 'This browser does not support passkeys.'); return;
  }
  inFlight = true;
  btn.disabled = true;
  btn.textContent = 'Waiting for your fingerprint...';
  show('busy', 'Your phone should be asking for your fingerprint now. Complete it, or dismiss it to cancel.');
  try {
    const cred = await navigator.credentials.create({
      publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(OPTIONS)
    });
    show('busy', 'Fingerprint accepted. Saving it to the server...');
    const resp = await fetch('/webauthn/register/complete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({session: SESSION, credential: cred.toJSON()})
    });
    const data = await resp.json();
    if (resp.ok) {
      done = true;
      btn.style.display = 'none';
      show('ok', 'Done. This device is registered. You can close this page. Next time you are asked to log in, use the "Sign in with passkey" button.');
    } else {
      show('err', data.error || 'Registration failed.');
      if (data.restart) offerRestart();
    }
  } catch (e) {
    show('err', e.name === 'NotAllowedError'
      ? 'Cancelled, or the prompt timed out. Tap the button to try again.'
      : ('Error: ' + e.message));
  } finally {
    inFlight = false;
    if (!done) { btn.disabled = false; btn.textContent = 'Register this device'; }
  }
});
</script>
</body></html>"""


def register_page_html(session_id: str, options_json: str) -> str:
    return (_REGISTER_PAGE
            .replace("__STYLE__", _STYLE)
            .replace("__SESSION__", json.dumps(session_id))
            .replace("__OPTIONS__", options_json))
