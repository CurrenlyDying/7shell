import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from auth_provider import SIGNATURE_NAMESPACE, ShellAuthProvider
from logcrypt import audit_encrypt
import webauthn_login

BASE_URL = os.environ["MCP_BASE_URL"].rstrip("/")
PORT = int(os.environ.get("PORT", "8811"))
HOST = os.environ.get("HOST", "127.0.0.1")

PUBLIC_HOSTNAME = urlparse(BASE_URL).hostname

AUDIT_LOG = Path(__file__).parent / "audit.log"

# Default working directory for run_command; the running user's home unless set.
DEFAULT_CWD = os.environ.get("MCP_DEFAULT_CWD", str(Path.home()))

# A session id plus an SSH signature block is a few hundred bytes; cap well
# above that so a malformed/oversized login POST can't force a large allocation.
MAX_LOGIN_BODY_BYTES = 16 * 1024
MAX_SIGNATURE_BYTES = 12 * 1024
MAX_WEBAUTHN_BODY_BYTES = 16 * 1024

provider = ShellAuthProvider(base_url=BASE_URL, login_path="/login")

mcp = FastMCP(
    "shell",
    host=HOST,
    port=PORT,
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(BASE_URL),
        resource_server_url=AnyHttpUrl(f"{BASE_URL}/mcp"),
        required_scopes=["shell"],
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["shell"],
            default_scopes=["shell"],
        ),
        revocation_options=RevocationOptions(enabled=True),
    ),
    # FastMCP auto-restricts Host/Origin to 127.0.0.1/localhost when bound to
    # loopback, which rejects every request arriving through the Cloudflare
    # tunnel (Host: your public hostname). Explicitly allow the public hostname
    # too, while keeping the DNS-rebinding protection itself turned on.
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[PUBLIC_HOSTNAME, f"{PUBLIC_HOSTNAME}:*", "127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*"],
        allowed_origins=[f"https://{PUBLIC_HOSTNAME}", "http://127.0.0.1:*", "http://localhost:*"],
    ),
)


def _client_ip(request: Request) -> str:
    return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "unknown")


def _audit(line: str) -> None:
    # Keep only the timestamp in cleartext (useful for "when did this happen"
    # triage); encrypt the detail to an offline public key. With no recipient
    # key installed the detail is written as-is (file is 0600) so nothing is
    # lost. The server cannot read its own encrypted logs back.
    ts = time.strftime('%Y-%m-%dT%H:%M:%S')
    fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(f"{ts} {audit_encrypt(line)}\n")


LOGIN_FORM = """<!doctype html>
<html><head><title>Sign in</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #111; color: #eee; display: flex;
       align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 2rem 0; }}
form {{ background: #1c1c1c; padding: 2rem; border-radius: 8px; width: 520px; max-width: 90vw;
        box-sizing: border-box; }}
code, pre {{ background: #2a2a2a; border: 1px solid #444; border-radius: 4px; padding: 0.15rem 0.4rem; }}
pre {{ padding: 0.8rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
textarea {{ width: 100%; padding: 0.6rem; margin-top: 0.5rem; margin-bottom: 1rem; box-sizing: border-box;
            background: #2a2a2a; border: 1px solid #444; color: #eee; border-radius: 4px;
            font-family: ui-monospace, monospace; font-size: 0.8rem; height: 8rem; }}
button {{ width: 100%; padding: 0.6rem; background: #4a4af0; color: white; border: none; border-radius: 4px;
          cursor: pointer; }}
.error {{ color: #ff6b6b; margin-bottom: 1rem; }}
ol {{ padding-left: 1.2rem; }}
li {{ margin-bottom: 0.6rem; }}
</style></head>
<body>
<form method="post" action="/login">
  <h2>Sign in with your SSH key</h2>
  {error}
  {webauthn_section}
  <input type="hidden" name="session" value="{session}">
  <p>Challenge code (tap to select):</p>
  <input readonly value="{nonce}" onclick="this.select()" style="width:100%;box-sizing:border-box;font-family:monospace;padding:6px">
  <ol>
    <li>Run this locally (adjust the key path if needed):<pre>printf '%s\\n' '{nonce}' &gt; ~/mcp-nonce.txt
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n {namespace} ~/mcp-nonce.txt
cat ~/mcp-nonce.txt.sig</pre></li>
    <li>Paste the resulting <code>-----BEGIN SSH SIGNATURE-----</code> block below.</li>
  </ol>
  <textarea name="signature" placeholder="-----BEGIN SSH SIGNATURE-----&#10;...&#10;-----END SSH SIGNATURE-----" autofocus></textarea>
  <button type="submit">Continue</button>
  <p style="text-align:center;margin-top:1rem;font-size:0.85rem"><a href="/webauthn/setup" style="color:#888">Set up a passkey</a></p>
</form>
</body></html>"""


@mcp.custom_route("/login", methods=["GET", "POST"])
async def login(request: Request):
    if request.method == "GET":
        session_id = request.query_params.get("session", "")
        nonce = provider.get_challenge(session_id)
        if nonce is None:
            return HTMLResponse("<h1>Login link expired or invalid</h1>", status_code=400)
        return HTMLResponse(LOGIN_FORM.format(
            error="", session=session_id, nonce=nonce, namespace=SIGNATURE_NAMESPACE,
            webauthn_section=webauthn_login.login_button_html(session_id),
        ))

    declared = request.headers.get("content-length")
    try:
        if declared is not None and int(declared) > MAX_LOGIN_BODY_BYTES:
            return HTMLResponse(webauthn_login.message_page_html("Request too large"), status_code=413)
    except ValueError:
        pass

    form = await request.form()
    session_id = str(form.get("session", ""))
    signature = str(form.get("signature", ""))
    if len(signature) > MAX_SIGNATURE_BYTES:
        return HTMLResponse(webauthn_login.message_page_html("Signature too large"), status_code=413)
    ip = _client_ip(request)

    nonce = provider.get_challenge(session_id)
    if nonce is None:
        return HTMLResponse("<h1>Login link expired or invalid</h1>", status_code=400)

    if provider.is_blocked(ip):
        _audit(f"LOGIN_RATE_LIMITED ip={ip}")
        return HTMLResponse(
            LOGIN_FORM.format(
                error='<div class="error">Too many attempts. Try again later.</div>',
                session=session_id, nonce=nonce, namespace=SIGNATURE_NAMESPACE,
                webauthn_section=webauthn_login.login_button_html(session_id),
            ),
            status_code=429,
        )

    if not provider.verify_signature(ip, session_id, signature):
        _audit(f"LOGIN_FAILED ip={ip}")
        return HTMLResponse(
            LOGIN_FORM.format(
                error='<div class="error">Signature did not verify.</div>',
                session=session_id, nonce=nonce, namespace=SIGNATURE_NAMESPACE,
                webauthn_section=webauthn_login.login_button_html(session_id),
            ),
            status_code=401,
        )

    redirect_url = provider.complete_login(session_id)
    if redirect_url is None:
        return HTMLResponse("<h1>Login link expired or invalid</h1>", status_code=400)

    _audit(f"LOGIN_OK ip={ip}")
    return RedirectResponse(url=redirect_url, status_code=302)


@mcp.custom_route("/webauthn/setup", methods=["GET", "POST"])
async def webauthn_setup(request: Request):
    if request.method == "GET":
        session_id, nonce = webauthn_login.start_setup()
        return HTMLResponse(webauthn_login.setup_form_html(session_id, nonce))

    declared = request.headers.get("content-length")
    try:
        if declared is not None and int(declared) > MAX_LOGIN_BODY_BYTES:
            return HTMLResponse(webauthn_login.message_page_html("Request too large"), status_code=413)
    except ValueError:
        pass

    form = await request.form()
    session_id = str(form.get("session", ""))
    signature = str(form.get("signature", ""))
    if len(signature) > MAX_SIGNATURE_BYTES:
        return HTMLResponse(webauthn_login.message_page_html("Signature too large"), status_code=413)
    ip = _client_ip(request)

    options_json, error, nonce = webauthn_login.verify_setup_signature_and_begin_registration(
        provider, ip, session_id, signature, rp_id=PUBLIC_HOSTNAME
    )
    if error:
        _audit(f"WEBAUTHN_SETUP_FAILED ip={ip}")
        if nonce is None:
            return HTMLResponse(webauthn_login.message_page_html("Setup link expired or invalid"), status_code=400)
        return HTMLResponse(webauthn_login.setup_form_html(session_id, nonce, error=error), status_code=401)

    _audit(f"WEBAUTHN_SETUP_OK ip={ip}")
    return HTMLResponse(webauthn_login.register_page_html(session_id, options_json))


def _read_webauthn_json_body(body) -> tuple[str, dict | None]:
    session_id = str(body.get("session", "")) if isinstance(body, dict) else ""
    credential = body.get("credential") if isinstance(body, dict) else None
    return session_id, credential if isinstance(credential, dict) else None


@mcp.custom_route("/webauthn/register/complete", methods=["POST"])
async def webauthn_register_complete(request: Request):
    declared = request.headers.get("content-length")
    try:
        if declared is not None and int(declared) > MAX_WEBAUTHN_BODY_BYTES:
            return JSONResponse({"error": "request too large"}, status_code=413)
    except ValueError:
        pass
    ip = _client_ip(request)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "malformed request"}, status_code=400)
    session_id, credential = _read_webauthn_json_body(body)

    if credential is None:
        ok, reason = False, "malformed"
    else:
        ok, reason = webauthn_login.complete_registration(
            session_id, credential, rp_id=PUBLIC_HOSTNAME, origin=BASE_URL
        )
    _audit(f"WEBAUTHN_REGISTER_{'OK' if ok else 'FAILED'} ip={ip} reason={reason}")
    if not ok:
        messages = {
            "session_gone": ("This setup code was already used, or it expired. "
                             "Get a fresh one to try again.", True),
            "verification_failed": ("Your device created a passkey but the server could not "
                                    "verify it. Get a fresh code and try again.", True),
            "malformed": ("Malformed request.", False),
        }
        msg, restart = messages.get(reason, ("Registration failed.", True))
        return JSONResponse({"error": msg, "restart": restart}, status_code=400)
    return JSONResponse({"ok": True})


@mcp.custom_route("/webauthn/authenticate/begin", methods=["POST"])
async def webauthn_authenticate_begin(request: Request):
    declared = request.headers.get("content-length")
    try:
        if declared is not None and int(declared) > MAX_WEBAUTHN_BODY_BYTES:
            return JSONResponse({"error": "request too large"}, status_code=413)
    except ValueError:
        pass
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "malformed request"}, status_code=400)
    session_id, _ = _read_webauthn_json_body(body)

    options_json = webauthn_login.begin_authentication(provider, session_id, rp_id=PUBLIC_HOSTNAME)
    if options_json is None:
        return JSONResponse({"error": "login link expired or invalid"}, status_code=400)
    return Response(content=options_json, media_type="application/json")


@mcp.custom_route("/webauthn/authenticate/complete", methods=["POST"])
async def webauthn_authenticate_complete(request: Request):
    declared = request.headers.get("content-length")
    try:
        if declared is not None and int(declared) > MAX_WEBAUTHN_BODY_BYTES:
            return JSONResponse({"error": "request too large"}, status_code=413)
    except ValueError:
        pass
    ip = _client_ip(request)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "malformed request"}, status_code=400)
    session_id, credential = _read_webauthn_json_body(body)

    if credential is None or not webauthn_login.verify_authentication(
        provider, ip, session_id, credential, rp_id=PUBLIC_HOSTNAME, origin=BASE_URL
    ):
        _audit(f"LOGIN_FAILED ip={ip} method=webauthn")
        return JSONResponse({"error": "passkey sign-in failed"}, status_code=401)

    redirect_url = provider.complete_login(session_id)
    if redirect_url is None:
        return JSONResponse({"error": "login link expired or invalid"}, status_code=400)
    _audit(f"LOGIN_OK ip={ip} method=webauthn")
    return JSONResponse({"redirect": redirect_url})


MAX_OUTPUT_CHARS = 100_000


def _truncate(s: str) -> str:
    if len(s) > MAX_OUTPUT_CHARS:
        return s[:MAX_OUTPUT_CHARS] + f"\n...[truncated, {len(s) - MAX_OUTPUT_CHARS} more chars]"
    return s


@mcp.tool()
def run_command(command: str, cwd: str = DEFAULT_CWD, timeout_seconds: int = 30) -> dict:
    """Run a shell command on this machine and return its exit code, stdout, and stderr.

    Args:
        command: The shell command to run (executed via `bash -lc`).
        cwd: Working directory to run the command in.
        timeout_seconds: Max time to allow the command to run, capped at 120s.
    """
    timeout_seconds = min(max(int(timeout_seconds), 1), 120)
    timed_out = False
    stdout = ""
    stderr = ""
    try:
        result = subprocess.run(
            ["bash", "-lc", command],
            cwd=cwd,
            timeout=timeout_seconds,
            capture_output=True,
            text=True,
        )
        exit_code = result.returncode
        stdout, stderr = result.stdout, result.stderr
    except subprocess.TimeoutExpired as e:
        exit_code = -1
        timed_out = True
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = (e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")) + "\n[command timed out]"
    except FileNotFoundError as e:
        exit_code = -1
        stderr = str(e)

    _audit(f"RUN exit={exit_code} cwd={cwd!r} command={command!r}")

    return {
        "exit_code": exit_code,
        "stdout": _truncate(stdout),
        "stderr": _truncate(stderr),
        "timed_out": timed_out,
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
