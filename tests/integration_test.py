"""Integration tests. Starts a real server on a spare port with a throwaway
database and a disposable signing key, then exercises it over HTTP.

    python tests/integration_test.py

Nothing here touches an installed instance: everything lives in a temporary
directory that is removed at the end. Exits non-zero if anything fails.

Cases that once passed and later turned out to be wrong are kept here on
purpose. A suite of happy paths is what let the first round of problems
through.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PORT = int(os.environ.get("TEST_PORT", "8971"))
BASE = f"http://127.0.0.1:{PORT}"
CALLBACK = "https://good.example.com/cb"

passed: list[str] = []
failed: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (passed if ok else failed).append(name)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail and not ok else ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """OAuth correctness depends on where a redirect points, so following one
    silently would hide exactly what these tests are checking."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def http(path, data=None, headers=None, method=None, raw=None):
    """Returns (status, body, location). Never raises on an HTTP error status."""
    url = BASE + path
    body = raw
    hdrs = dict(headers or {})
    if data is not None and raw is None:
        if hdrs.get("Content-Type") == "application/json":
            body = json.dumps(data).encode()
        else:
            body = "&".join(
                f"{k}={urllib.parse.quote(str(v))}" for k, v in data.items()
            ).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with _opener.open(req) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers.get("Location")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers.get("Location")


import urllib.parse  # noqa: E402  (used by http())


class Server:
    def __init__(self, tmp: Path, extra_env: dict | None = None):
        self.tmp = tmp
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(tmp / "home"),
            "MCP_BASE_URL": BASE,
            "HOST": "127.0.0.1",
            "PORT": str(PORT),
            "MCP_SIGNATURE_PRINCIPAL": "test-principal",
            "MCP_ALLOWED_REDIRECT_URIS": CALLBACK,
        }
        self.env.update(extra_env or {})
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "server.py"], cwd=self.tmp, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for _ in range(80):
            time.sleep(0.25)
            if self.proc.poll() is not None:
                raise RuntimeError("server exited:\n" + (self.proc.stdout.read() or ""))
            try:
                if http("/.well-known/oauth-authorization-server")[0] == 200:
                    return self
            except OSError:
                continue
        raise RuntimeError("server did not come up")

    def __exit__(self, *exc):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def make_tmp() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="7shell-test-"))
    for f in REPO.glob("*.py"):
        shutil.copy(f, tmp)
    (tmp / "home").mkdir()
    (tmp / "data").mkdir()
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp / "key")], check=True)
    (tmp / "data" / "allowed_signers").write_text(
        "test-principal " + (tmp / "key.pub").read_text().strip() + "\n"
    )
    return tmp


def register(callback=CALLBACK, name="TestApp", **extra):
    body = {"client_name": name, "redirect_uris": [callback],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "token_endpoint_auth_method": "none",
            "scope": "shell"}
    body.update(extra)
    return http("/register", body, {"Content-Type": "application/json"})


def sign(tmp: Path, nonce: str, namespace="mcp-login") -> str:
    f = tmp / "nonce.txt"
    f.write_text(nonce + "\n")
    sig = tmp / "nonce.txt.sig"
    if sig.exists():
        sig.unlink()
    subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(tmp / "key"),
                    "-n", namespace, str(f)], check=True)
    return sig.read_text()


def full_login(tmp, client_id, callback=CALLBACK, resource=None):
    """Returns (access_token, refresh_token)."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"response_type": "code", "client_id": client_id, "redirect_uri": callback,
         "code_challenge": challenge, "code_challenge_method": "S256",
         "state": "st", "scope": "shell"}
    if resource:
        q["resource"] = resource
    status, _, location = http("/authorize?" + urllib.parse.urlencode(q))
    if not location:
        raise RuntimeError(f"authorize did not redirect to login (status {status})")
    session = re.search(r"session=([\w\-]+)", location).group(1)

    _, page, _ = http(f"/login?session={session}")
    nonce = re.search(r'<input readonly value="([\w\-]+)"', page).group(1)
    _, _, redirect = http("/login", {"session": session, "signature": sign(tmp, nonce)})
    if not redirect:
        raise RuntimeError("login did not redirect back to the client")
    code = re.search(r"code=([\w\-]+)", redirect).group(1)

    form = {"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "client_id": client_id, "redirect_uri": callback}
    if resource:
        form["resource"] = resource
    _, body, _ = http("/token", form)
    tok = json.loads(body)
    return tok.get("access_token"), tok.get("refresh_token")


def mcp_works(token) -> bool:
    status, _, _ = http("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "t", "version": "1"}}},
                     {"Authorization": f"Bearer {token}",
                      "Accept": "application/json, text/event-stream",
                      "Content-Type": "application/json"})
    return status == 200


# --------------------------------------------------------------------------
# The cases the second review found. Each one failed before the fix.
# --------------------------------------------------------------------------

def test_regressions(tmp):
    # A token predating grant tracking cannot be revoked as part of a grant, so
    # it is invalidated at startup instead of being kept in that state. One run
    # first, to create the schema this inserts into.
    with Server(tmp):
        pass
    db = sqlite3.connect(tmp / "data" / "store.sqlite3")
    db.execute("INSERT INTO access_tokens (token, client_id, scopes, expires_at, grant_id)"
               " VALUES ('legacyhash', 'c', 'shell', ?, NULL)", (int(time.time()) + 9999,))
    db.commit(); db.close()
    with Server(tmp):
        db = sqlite3.connect(tmp / "data" / "store.sqlite3")
        left = db.execute("SELECT count(*) FROM access_tokens WHERE grant_id IS NULL").fetchone()[0]
        db.close()
        check("legacy grantless token invalidated on start", left == 0, f"{left} left")

    with Server(tmp) as s:
        # Exact callback matching. A prefix would accept both of these.
        check("suffixed host rejected",
              register("https://good.example.com.attacker.invalid/cb")[0] == 400)
        check("extended path rejected", register(CALLBACK + "-attacker")[0] == 400)
        check("exact callback accepted", register(CALLBACK)[0] == 201)

        # Setup sessions are capped by the endpoint that creates them, not only
        # by a sweep that unauthenticated traffic never triggers.
        for _ in range(25):
            http("/webauthn/setup")
        db = sqlite3.connect(tmp / "data" / "store.sqlite3")
        rows = db.execute("SELECT count(*) FROM webauthn_setup_sessions").fetchone()[0]
        db.close()
        check("setup sessions capped at 20", rows <= 20, f"{rows} rows")

        # The SDK's own routes are behind the body limit too.
        status, _, _ = register(CALLBACK, name="x" * 2_000_000)
        check("oversized registration rejected", status == 413, f"got {status}")

        # Grant revocation on a current token.
        cid = json.loads(register(CALLBACK)[1])["client_id"]
        at, rt = full_login(tmp, cid)
        check("fresh token works", mcp_works(at))
        http("/revoke", {"token": rt, "client_id": cid})
        check("revoking refresh kills sibling access token", not mcp_works(at))

        # Rotation, then revoke the replacement: the original must be gone too.
        at1, rt1 = full_login(tmp, cid)
        tok = json.loads(http("/token", {"grant_type": "refresh_token",
                                         "refresh_token": rt1, "client_id": cid,
                                         "scope": "shell"})[1])
        http("/revoke", {"token": tok["refresh_token"], "client_id": cid})
        check("revoking a rotated grant kills the original access token", not mcp_works(at1))
        check("revoking a rotated grant kills the new access token", not mcp_works(tok["access_token"]))


def test_resource_case(tmp):
    # Path case is significant in a URL; only scheme and host are not. Canonical
    # form must not lowercase the path or two different resources compare equal.
    sys.path.insert(0, str(tmp))
    for mod in ("auth_provider", "config", "logcrypt", "webauthn_login", "server"):
        sys.modules.pop(mod, None)
    os.environ["MCP_SIGNATURE_PRINCIPAL"] = "test-principal"
    import auth_provider
    check("host case ignored",
          auth_provider._canon("HTTPS://Example.COM/Path") == "https://example.com/Path")
    check("path case preserved",
          auth_provider._canon("https://e.com/Path") != auth_provider._canon("https://e.com/path"))
    check("trailing slash ignored",
          auth_provider._canon("https://e.com/p/") == auth_provider._canon("https://e.com/p"))
    sys.path.remove(str(tmp))


def test_cancellation_race(tmp):
    """Cancel before the worker reaches Popen. The command must never start."""
    sys.path.insert(0, str(tmp))
    for mod in ("auth_provider", "config", "logcrypt", "webauthn_login", "server"):
        sys.modules.pop(mod, None)
    os.environ.update({"MCP_BASE_URL": BASE, "MCP_ALLOWED_REDIRECT_URIS": CALLBACK,
                       "MCP_SIGNATURE_PRINCIPAL": "test-principal"})
    import server as srv

    job = srv._Job()
    job.cancel()                       # cancellation wins the race
    marker = tmp / "should-not-exist"
    started = job.start(["bash", "-lc", f"touch {marker}"], str(tmp))
    time.sleep(0.5)
    check("cancelled job refuses to start a process", started is None)
    check("cancelled job ran nothing", not marker.exists())

    job2 = srv._Job()
    proc = job2.start(["bash", "-lc", "sleep 30"], str(tmp))
    check("uncancelled job starts", proc is not None)
    check("cancel kills a running job", job2.cancel())
    time.sleep(0.5)
    check("killed job is dead", proc.poll() is not None)
    sys.path.remove(str(tmp))


def test_audit_required_at_write_time(tmp):
    """Removing the key while running must not silently downgrade to plaintext."""
    sys.path.insert(0, str(tmp))
    for mod in ("auth_provider", "config", "logcrypt", "webauthn_login", "server"):
        sys.modules.pop(mod, None)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = X25519PrivateKey.generate()
    pub = tmp / "data" / "log_recipient.pub"
    pub.write_text(base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
    os.environ.update({"MCP_BASE_URL": BASE, "MCP_ALLOWED_REDIRECT_URIS": CALLBACK,
                       "MCP_SIGNATURE_PRINCIPAL": "test-principal",
                       "MCP_REQUIRE_AUDIT_KEY": "1"})
    import server as srv
    srv._audit("TEST encrypted")
    check("audit works with a key present", "ENC" in (tmp / "audit.log").read_text())

    pub.unlink()                       # key disappears while running
    raised = False
    try:
        srv._audit("TEST after key removal")
    except srv.AuditUnavailable:
        raised = True
    check("audit refuses to write plaintext when a key is required", raised)
    check("no plaintext line was appended",
          "TEST after key removal" not in (tmp / "audit.log").read_text())
    del os.environ["MCP_REQUIRE_AUDIT_KEY"]
    sys.path.remove(str(tmp))


def main() -> int:
    tmp = make_tmp()
    try:
        test_regressions(tmp)
        test_resource_case(tmp)
        test_cancellation_race(tmp)
        test_audit_required_at_write_time(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    if failed:
        print("FAILED: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
