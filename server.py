import functools
import html
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import anyio
import anyio.to_thread
from pydantic import AnyHttpUrl

import config

# Configuration has to be resolved before anything that reads it at import time,
# which is why this call sits above the remaining imports rather than with the
# rest of the startup code. With no .env and no terminal this exits with an
# explanation; with a terminal it runs first-run setup.
config.ensure_configured(force="--setup" in sys.argv)
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from mcp.server.auth.handlers.revoke import RevocationRequest
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from auth_provider import (
    ALLOWED_REDIRECT_URIS,
    SIGNATURE_NAMESPACE,
    USING_LEGACY_REDIRECT_VAR,
    ShellAuthProvider,
)
from logcrypt import AuditKeyUnavailable, audit_encrypt, key_available
import webauthn_login

BASE_URL = os.environ["MCP_BASE_URL"].rstrip("/")
PORT = int(os.environ.get("PORT", "8811"))
HOST = os.environ.get("HOST", "127.0.0.1")

PUBLIC_HOSTNAME = urlparse(BASE_URL).hostname

AUDIT_LOG = Path(__file__).parent / "audit.log"

# Default working directory for run_command; the running user's home unless set.
DEFAULT_CWD = os.environ.get("MCP_DEFAULT_CWD", str(Path.home()))

# Optionally run commands as a different, less privileged OS user. Requires a
# sudoers rule permitting it without a password. Unset means commands run as the
# same user as this server, which can then modify its own auth state.
EXEC_USER = os.environ.get("MCP_EXEC_USER", "").strip()

# Commands run in worker threads (see run_command). Bound how many can be in
# flight at once with a limiter of their own, so a burst of slow commands queues
# instead of eating the shared thread pool the rest of the app relies on.
MAX_CONCURRENT_COMMANDS = max(1, int(os.environ.get("MCP_MAX_CONCURRENT_COMMANDS", "8")))
_command_limiter = anyio.CapacityLimiter(MAX_CONCURRENT_COMMANDS)

# Refuse to start rather than fall back to plaintext audit lines.
REQUIRE_AUDIT_KEY = os.environ.get("MCP_REQUIRE_AUDIT_KEY", "") == "1"
if REQUIRE_AUDIT_KEY and not key_available():
    raise SystemExit(
        "MCP_REQUIRE_AUDIT_KEY=1 but data/log_recipient.pub is missing or invalid; "
        "install a valid X25519 recipient key or unset the variable."
    )
if not ALLOWED_REDIRECT_URIS:
    print(
        "WARNING: MCP_ALLOWED_REDIRECT_URIS is unset, so no client can register. "
        "Set it to the callback URLs you trust.",
        flush=True,
    )
if USING_LEGACY_REDIRECT_VAR:
    print(
        "NOTE: MCP_ALLOWED_REDIRECT_PREFIXES is deprecated and its values are now "
        "matched exactly rather than as prefixes. Rename it to "
        "MCP_ALLOWED_REDIRECT_URIS and list full callback URLs.",
        flush=True,
    )
if EXEC_USER:
    # Checked once at startup rather than discovered on every command. The most
    # common cause of failure is a service unit with NoNewPrivileges=yes, which
    # blocks the setuid transition sudo needs and cannot be overridden by a
    # sudoers rule.
    _probe = subprocess.run(
        ["sudo", "-n", "-u", EXEC_USER, "true"], capture_output=True, text=True
    )
    if _probe.returncode != 0:
        raise SystemExit(
            f"MCP_EXEC_USER={EXEC_USER} but switching to that account failed: "
            f"{(_probe.stderr or '').strip() or 'no error output'}\n"
            "The account must exist, this service needs a passwordless sudoers rule "
            "for it, and the unit must not set NoNewPrivileges=yes, which blocks the "
            "transition sudo requires."
        )

# A session id plus an SSH signature block is a few hundred bytes; cap well
# above that so a malformed/oversized login POST can't force a large allocation.
MAX_LOGIN_BODY_BYTES = 16 * 1024
MAX_SIGNATURE_BYTES = 12 * 1024
MAX_WEBAUTHN_BODY_BYTES = 16 * 1024

# The SDK declares client_secret on the revocation request as `str | None` with
# no default, so pydantic treats it as required and a public client that simply
# omits it gets a 400. Revocation then only works if the caller sends an empty
# string, which no correct client does. Give the field a default when the
# installed SDK still has the bug; a fixed version makes this a no-op.
_revoke_secret = RevocationRequest.model_fields.get("client_secret")
if _revoke_secret is not None and _revoke_secret.is_required():
    _revoke_secret.default = None
    RevocationRequest.model_rebuild(force=True)

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


# The encryption layer owns this, so the check and the encryption cannot
# disagree about which key was present.
AuditUnavailable = AuditKeyUnavailable


def _audit_quietly(line: str) -> None:
    """Audit where the caller has nothing useful to do about a failure, such as
    after the command has already run. The event is reported rather than lost."""
    try:
        _audit(line)
    except AuditUnavailable as e:
        print(f"AUDIT FAILED, event not recorded: {e}: {line}", file=sys.stderr, flush=True)


def _client_ip(request: Request) -> str:
    return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "unknown")


_audit_lock = threading.Lock()


def _audit(line: str) -> None:
    # Keep only the timestamp in cleartext (useful for "when did this happen"
    # triage); encrypt the detail to an offline public key. With no recipient
    # key installed the detail is written as-is (file is 0600) so nothing is
    # lost. The server cannot read its own encrypted logs back.
    ts = time.strftime('%Y-%m-%dT%H:%M:%S')
    # Enforced per write and inside the encryption itself, not by a separate
    # check beforehand. A key removed between a check and the encryption would
    # pass the check and be written in plaintext regardless.
    line = f"{ts} {audit_encrypt(line, require=REQUIRE_AUDIT_KEY)}\n"
    # Serialised because commands are audited from worker threads now, and an
    # encrypted line is well over the size the kernel appends atomically.
    with _audit_lock:
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(line)


async def _read_body_limited(request: Request, max_bytes: int) -> bytes | None:
    """Read the request body, giving up past max_bytes. Content-Length is a claim,
    not a guarantee, and is absent entirely on a chunked request, so the cap has
    to be applied to bytes actually received rather than to the header."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                return None
        except ValueError:
            return None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _form_field(body: bytes, name: str) -> str:
    values = parse_qs(body.decode("utf-8", "replace")).get(name)
    return values[0] if values else ""


def _json_body(body: bytes) -> dict | None:
    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


GRANT_BOX = """<div class="grant">
  <p><strong>{client_name}</strong> is asking for <strong>shell access</strong> to this machine.</p>
  <p class="mono">client id: {client_id}<br>sends the code to: {redirect_uri}<br>scopes: {scopes}</p>
  <p>Continue only if you started this from that application. Signing below lets it
  run commands as this user until you revoke it.</p>
</div>"""


def _grant_box(session_id: str) -> str:
    ctx = provider.get_login_context(session_id)
    if ctx is None:
        return ""
    return GRANT_BOX.format(**{k: html.escape(str(v)) for k, v in ctx.items()})


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
.grant {{ background: #23201a; border: 1px solid #6a5a2a; border-radius: 6px;
          padding: 0.9rem 1rem; margin-bottom: 1.2rem; font-size: 0.9rem; }}
.grant p {{ margin: 0 0 0.6rem 0; }}
.grant p:last-child {{ margin-bottom: 0; }}
.mono {{ font-family: ui-monospace, monospace; font-size: 0.78rem; color: #bbb; word-break: break-all; }}
ol {{ padding-left: 1.2rem; }}
li {{ margin-bottom: 0.6rem; }}
</style></head>
<body>
<form method="post" action="/login">
  <h2>Sign in with your SSH key</h2>
  {error}
  {grant_box}
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
  <button type="submit">Grant shell access</button>
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
            grant_box=_grant_box(session_id),
            webauthn_section=webauthn_login.login_button_html(session_id),
        ))

    body = await _read_body_limited(request, MAX_LOGIN_BODY_BYTES)
    if body is None:
        return HTMLResponse(webauthn_login.message_page_html("Request too large"), status_code=413)
    session_id = _form_field(body, "session")
    signature = _form_field(body, "signature")
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
                grant_box=_grant_box(session_id),
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
                grant_box=_grant_box(session_id),
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
    ip = _client_ip(request)
    if request.method == "GET":
        # Unauthenticated and it writes a row, so it needs the same per-IP budget
        # as a login attempt or it is a free way to grow the database.
        # Its own budget, separate from login. Sharing one would mean a few
        # visits to this page locked the operator out of signing in.
        if provider.is_blocked(ip, "webauthn-setup"):
            _audit_quietly(f"WEBAUTHN_SETUP_RATE_LIMITED ip={ip}")
            return HTMLResponse(
                webauthn_login.message_page_html("Too many attempts. Try again later."),
                status_code=429,
            )
        provider.record_failed_attempt(ip, "webauthn-setup")
        session_id, nonce = webauthn_login.start_setup()
        return HTMLResponse(webauthn_login.setup_form_html(session_id, nonce))

    body = await _read_body_limited(request, MAX_LOGIN_BODY_BYTES)
    if body is None:
        return HTMLResponse(webauthn_login.message_page_html("Request too large"), status_code=413)
    session_id = _form_field(body, "session")
    signature = _form_field(body, "signature")
    if len(signature) > MAX_SIGNATURE_BYTES:
        return HTMLResponse(webauthn_login.message_page_html("Signature too large"), status_code=413)

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
    ip = _client_ip(request)
    raw = await _read_body_limited(request, MAX_WEBAUTHN_BODY_BYTES)
    if raw is None:
        return JSONResponse({"error": "request too large"}, status_code=413)
    body = _json_body(raw)
    if body is None:
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
    raw = await _read_body_limited(request, MAX_WEBAUTHN_BODY_BYTES)
    if raw is None:
        return JSONResponse({"error": "request too large"}, status_code=413)
    body = _json_body(raw)
    if body is None:
        return JSONResponse({"error": "malformed request"}, status_code=400)
    session_id, _ = _read_webauthn_json_body(body)

    options_json = webauthn_login.begin_authentication(provider, session_id, rp_id=PUBLIC_HOSTNAME)
    if options_json is None:
        return JSONResponse({"error": "login link expired or invalid"}, status_code=400)
    return Response(content=options_json, media_type="application/json")


@mcp.custom_route("/webauthn/authenticate/complete", methods=["POST"])
async def webauthn_authenticate_complete(request: Request):
    ip = _client_ip(request)
    raw = await _read_body_limited(request, MAX_WEBAUTHN_BODY_BYTES)
    if raw is None:
        return JSONResponse({"error": "request too large"}, status_code=413)
    body = _json_body(raw)
    if body is None:
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
# Hard ceiling on bytes retained per stream. The character truncation below only
# shortens what is shown; without this the whole output is already in memory by
# then, so a command producing gigabytes takes the server down before any limit
# applies.
MAX_OUTPUT_BYTES = 2 * 1024 * 1024


def _truncate(s: str) -> str:
    if len(s) > MAX_OUTPUT_CHARS:
        return s[:MAX_OUTPUT_CHARS] + f"\n...[truncated, {len(s) - MAX_OUTPUT_CHARS} more chars]"
    return s


def _drain(stream, sink: dict) -> None:
    """Read a pipe to EOF, keeping at most MAX_OUTPUT_BYTES and counting the rest.
    Draining rather than stopping keeps the child from blocking on a full pipe."""
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            room = MAX_OUTPUT_BYTES - sink["kept"]
            if room > 0:
                sink["parts"].append(chunk[:room])
                sink["kept"] += min(room, len(chunk))
            sink["dropped"] += max(0, len(chunk) - max(room, 0))
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _finish(sink: dict) -> str:
    text = b"".join(sink["parts"]).decode("utf-8", "replace")
    if sink["dropped"]:
        text += f"\n...[dropped {sink['dropped']} further bytes]"
    return text


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the whole process group. subprocess's own timeout kills only the
    direct child, so `bash -lc 'sleep 999 &'` outlives it."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


class _Job:
    """Shared state between the worker thread running a command and the request
    that may be cancelled out from under it.

    Without the flag there is a window: cancellation arrives, finds no process
    handle because the worker has not reached Popen yet, kills nothing, and the
    abandoned worker then starts the command anyway. Claiming the job under a
    lock closes it. Either cancel sees the process and kills it, or it marks the
    job dead before the process exists and the worker never starts one.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._cancelled = False

    def start(self, argv: list[str], cwd: str) -> subprocess.Popen | None:
        with self._lock:
            if self._cancelled:
                return None
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # own process group, so the tree is killable
            )
            self._proc = proc
            return proc

    def cancel(self) -> bool:
        with self._lock:
            self._cancelled = True
            proc = self._proc
        if proc is not None:
            _kill_tree(proc)
            return True
        return False


def _run_command_blocking(command: str, cwd: str, timeout_seconds: int, job: _Job) -> dict:
    """The actual work. Runs on a worker thread; never call this from the loop."""
    argv = ["bash", "-lc", command]
    if EXEC_USER:
        argv = ["sudo", "-n", "-u", EXEC_USER] + argv

    # Logged before execution, so a command that takes the server down with it
    # still leaves a record that it was attempted. If the audit line cannot be
    # written under the guarantee configured, the command does not run at all.
    try:
        _audit(f"RUN_START user={EXEC_USER or 'self'} cwd={cwd!r} command={command!r}")
    except AuditUnavailable as e:
        return {"exit_code": -1, "stdout": "", "stderr": f"refused: {e}", "timed_out": False}

    out = {"parts": [], "kept": 0, "dropped": 0}
    err = {"parts": [], "kept": 0, "dropped": 0}
    timed_out = False
    try:
        proc = job.start(argv, cwd)
    except (FileNotFoundError, NotADirectoryError, PermissionError) as e:
        _audit_quietly(f"RUN_END exit=-1 error={e!r}")
        return {"exit_code": -1, "stdout": "", "stderr": str(e), "timed_out": False}
    if proc is None:
        # Cancelled before the process existed. Nothing ran.
        _audit_quietly("RUN_CANCELLED before_start=1")
        return {"exit_code": -1, "stdout": "", "stderr": "cancelled", "timed_out": False}

    readers = [
        threading.Thread(target=_drain, args=(proc.stdout, out), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, err), daemon=True),
    ]
    for r in readers:
        r.start()
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    for r in readers:
        r.join(timeout=5)

    exit_code = proc.returncode if proc.returncode is not None else -1
    stdout, stderr = _finish(out), _finish(err)
    if timed_out:
        stderr += "\n[command timed out; process group killed]"

    _audit_quietly(f"RUN_END exit={exit_code} timed_out={timed_out} bytes={out['kept'] + err['kept']}")

    return {
        "exit_code": exit_code,
        "stdout": _truncate(stdout),
        "stderr": _truncate(stderr),
        "timed_out": timed_out,
    }


@mcp.tool()
async def run_command(command: str, cwd: str = DEFAULT_CWD, timeout_seconds: int = 30) -> dict:
    """Run a shell command on this machine and return its exit code, stdout, and stderr.

    Args:
        command: The shell command to run (executed via `bash -lc`).
        cwd: Working directory to run the command in.
        timeout_seconds: Max time to allow the command to run, capped at 120s.
    """
    timeout_seconds = min(max(int(timeout_seconds), 1), 120)

    # The SDK calls a synchronous tool function directly on the event loop, so a
    # blocking implementation stops the server answering anything at all for the
    # duration, up to the full timeout. Auth endpoints included. Run the blocking
    # part on a worker thread and keep the loop free.
    job = _Job()
    try:
        return await anyio.to_thread.run_sync(
            functools.partial(_run_command_blocking, command, cwd, timeout_seconds, job),
            abandon_on_cancel=True,
            limiter=_command_limiter,
        )
    except anyio.get_cancelled_exc_class():
        # Client went away. The worker thread is abandoned, so the child has to be
        # dealt with here; and if it has not started yet, prevented from starting.
        if job.cancel():
            _audit_quietly("RUN_CANCELLED killed=1")
        else:
            _audit_quietly("RUN_CANCELLED killed=0")
        raise


MAX_REQUEST_BYTES = int(os.environ.get("MCP_MAX_REQUEST_BYTES", str(1024 * 1024)))

# Methods that can carry a body. Anything else is passed straight through: the
# GET on the MCP endpoint is a long-lived event stream, and reading from it here
# waiting for a body that never comes would stall the request.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


class BodyLimit:
    """ASGI wrapper capping the body of every request.

    The per-endpoint limits only cover the routes written in this module.
    Registration, token and authorize are served by the SDK and had no limit at
    all, so a request with a megabyte-long client name was accepted and stored.

    The body is read here, before the application sees it, and the request is
    refused outright if it runs over. An earlier version let the read raise
    through the application instead, which the SDK's own error middleware caught
    first and turned into a 500 before this wrapper could answer. Reading first
    means the limit is decided in one place and the answer is always 413.

    Bodies are therefore buffered up to the limit. That is fine for what this
    server receives, since every request body here is a complete JSON or form
    document rather than a stream.
    """

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method", "").upper() not in _BODY_METHODS:
            return await self.app(scope, receive, send)

        # Content-Length is a claim and is absent on a chunked request, so it is
        # only ever used to refuse early, never to decide that a body is small.
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        return await self._reject(send)
                except ValueError:
                    return await self._reject(send)

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")
            if len(body) > self.max_bytes:
                return await self._reject(send)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            # Anything after the body comes from the real transport. Returning a
            # fabricated disconnect here instead tells a streaming response that
            # the client has gone, and truncates it mid-stream.
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(self, send) -> None:
        payload = b'{"error":"request too large"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"),
                        (b"content-length", str(len(payload)).encode())],
        })
        await send({"type": "http.response.body", "body": payload})


if __name__ == "__main__":
    import uvicorn

    # Built here rather than via mcp.run() so the body limit can be wrapped
    # around the SDK's routes as well as this module's.
    uvicorn.run(
        BodyLimit(mcp.streamable_http_app(), MAX_REQUEST_BYTES),
        host=HOST,
        port=PORT,
        log_level="info",
    )
