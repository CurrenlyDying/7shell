"""Minimal single-user OAuth 2.1 authorization server for the shell MCP server.

Implements mcp.server.auth.provider.OAuthAuthorizationServerProvider. The MCP SDK's
routes/handlers already take care of every protocol detail that matters to Claude
(401 + WWW-Authenticate gating, RFC 9728 / RFC 8414 metadata, DCR, PKCE verification,
form-urlencoded /token). This module only supplies storage and the one thing the SDK
can't know: how to actually authenticate the human. That happens in server.py's
/login custom route, which calls start_login()/complete_login() below.
"""

import hashlib
import os
import secrets
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse

from pydantic import AnyUrl

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

DB_PATH = Path(__file__).parent / "data" / "store.sqlite3"
ALLOWED_SIGNERS_PATH = Path(__file__).parent / "data" / "allowed_signers"

ACCESS_TOKEN_TTL_SECONDS = 8 * 60 * 60
REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60
AUTH_CODE_TTL_SECONDS = 120
LOGIN_SESSION_TTL_SECONDS = 10 * 60

# The identity string checked against ALLOWED_SIGNERS_PATH (the -I principal)
# and the namespace ssh-keygen -Y sign/verify must agree on (the -n value).
# Both are arbitrary but must match what's in the login page instructions.
# Set MCP_SIGNATURE_PRINCIPAL to whatever principal you used in allowed_signers.
SIGNATURE_PRINCIPAL = os.environ.get("MCP_SIGNATURE_PRINCIPAL", "mcp-user")
SIGNATURE_NAMESPACE = "mcp-login"

# Registration allowlist. Dynamic client registration is open by protocol, so
# without this anyone can register a client pointing at their own callback, send
# you its authorize link, and receive the code when you sign in on your own real
# domain. Proving you hold the key says nothing about who you are granting to,
# so the set of acceptable callbacks has to be pinned out of band.
#
# Matching is exact, not by prefix. A prefix of "https://good.example" also
# matches "https://good.example.attacker.invalid/cb", and a prefix ending "/cb"
# also matches "/cb-attacker". Whether an operator's setting is safe should not
# depend on remembering that.
_LEGACY_REDIRECT_ENV = os.environ.get("MCP_ALLOWED_REDIRECT_PREFIXES", "")
_REDIRECT_ENV = os.environ.get("MCP_ALLOWED_REDIRECT_URIS", "")
# True whenever the deprecated name is present, including after config.py has
# copied its value across, so the notice still prints.
USING_LEGACY_REDIRECT_VAR = bool(_LEGACY_REDIRECT_ENV)

# Login rate limiting: per source IP, max attempts within the window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60

# Housekeeping: how many token-less client rows to keep, how many pending passkey
# setup sessions to keep, and how often expired rows get swept.
MAX_TOKENLESS_CLIENTS = 3
MAX_SETUP_SESSIONS = 20
PURGE_INTERVAL_SECONDS = 60


def _canon(url: str | None) -> str | None:
    """Canonical form for comparing URLs.

    Scheme and host are case-insensitive per RFC 3986; the path is not, so
    lowercasing the whole string would make /Callback and /callback the same
    thing. Only a trailing slash is normalised away.
    """
    if not url:
        return None
    parsed = urlparse(str(url))
    if not parsed.scheme or not parsed.netloc:
        return str(url).rstrip("/")
    rest = parsed.path.rstrip("/")
    if parsed.query:
        rest += "?" + parsed.query
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{rest}"


ALLOWED_REDIRECT_URIS = tuple(
    c for c in (_canon(u) for u in (_REDIRECT_ENV or _LEGACY_REDIRECT_ENV).split(",") if u.strip()) if c
)


def redirect_uri_allowed(uri: str | None) -> bool:
    """Exact match against the allowlist. Empty allowlist permits nothing."""
    return bool(ALLOWED_REDIRECT_URIS) and _canon(uri) in ALLOWED_REDIRECT_URIS

_lock = Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _hash_token(token: str) -> str:
    """One-way hash for storing bearer tokens at rest. Tokens are 256-bit
    CSPRNG values, so a single SHA-256 is enough: there is nothing to
    brute-force, and the raw token never touches disk."""
    return hashlib.sha256(token.encode()).hexdigest()


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_sessions (
                session_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                state TEXT,
                scopes TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                redirect_uri_explicit INTEGER NOT NULL,
                resource TEXT,
                expires_at REAL NOT NULL,
                nonce TEXT
            );
            CREATE TABLE IF NOT EXISTS auth_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                redirect_uri_explicit INTEGER NOT NULL,
                resource TEXT,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS access_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                expires_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scopes TEXT NOT NULL,
                expires_at INTEGER
            );
            """
        )
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS used_refresh_tokens (
                token TEXT PRIMARY KEY,
                grant_id TEXT,
                used_at REAL NOT NULL
            );
            """
        )
        # Migrations. Each is a no-op once the column exists, so upgrading in
        # place never invalidates a live session.
        for table, coldef in (
            ("login_sessions", "nonce TEXT"),
            ("access_tokens", "grant_id TEXT"),
            ("access_tokens", "resource TEXT"),
            ("refresh_tokens", "grant_id TEXT"),
            ("refresh_tokens", "resource TEXT"),
        ):
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")
            except sqlite3.OperationalError:
                pass

        # A token with no grant cannot be revoked as part of one: revoking it
        # deletes only itself and leaves its siblings working. Nothing was ever
        # stored that says which tokens belonged together, so they cannot be
        # repaired, only kept in a state where revocation silently under-deletes.
        # They are invalidated instead. The cost is reconnecting once. This stays
        # in place permanently as an invariant: no grant, no token.
        orphaned = sum(
            conn.execute(f"DELETE FROM {table} WHERE grant_id IS NULL").rowcount
            for table in ("access_tokens", "refresh_tokens")
        )
        if orphaned:
            print(
                f"Invalidated {orphaned} token(s) issued before grant tracking; "
                "they could not be revoked as a grant. Reconnect the client to sign in again.",
                flush=True,
            )


def _migrate_plaintext_tokens() -> None:
    """Convert any pre-existing raw tokens (43-char urlsafe) to their hash
    (64-char hex) in place, so upgrading never invalidates a live session.
    Idempotent: rows already hashed (len 64) are left alone."""
    with _lock, _connect() as conn:
        for table in ("access_tokens", "refresh_tokens"):
            for row in conn.execute(f"SELECT token FROM {table}").fetchall():
                tok = row["token"]
                if len(tok) != 64:
                    conn.execute(
                        f"UPDATE {table} SET token = ? WHERE token = ?",
                        (_hash_token(tok), tok),
                    )


_init_db()
_migrate_plaintext_tokens()


# A client row is worth keeping if it holds tokens OR has an authorization in
# flight (a pending code or an open login session). The earlier version checked
# tokens only, so three registrations could evict a client that was still part
# way through connecting.
_LIVE_CLIENT_PREDICATE = """
    client_id IN (SELECT client_id FROM access_tokens)
 OR client_id IN (SELECT client_id FROM refresh_tokens)
 OR client_id IN (SELECT client_id FROM auth_codes)
 OR client_id IN (SELECT client_id FROM login_sessions)
"""

_CLIENT_RETENTION_SQL = f"""
DELETE FROM clients
 WHERE NOT ({_LIVE_CLIENT_PREDICATE})
   AND client_id NOT IN (
       SELECT client_id FROM clients
        WHERE NOT ({_LIVE_CLIENT_PREDICATE})
        ORDER BY rowid DESC
        LIMIT {MAX_TOKENLESS_CLIENTS}
   )
"""

_last_purge = 0.0


def _purge_expired(force: bool = False) -> None:
    """Delete rows that are past their expiry, and cap unbounded public state.

    Nothing here is reachable only by an authenticated caller, so without a sweep
    anonymous traffic can grow the database indefinitely. Throttled so it can be
    called freely from request paths.
    """
    global _last_purge
    now = time.time()
    if not force and now - _last_purge < PURGE_INTERVAL_SECONDS:
        return
    _last_purge = now
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM login_sessions WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM access_tokens WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        conn.execute("DELETE FROM refresh_tokens WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        conn.execute("DELETE FROM used_refresh_tokens WHERE used_at < ?", (now - REFRESH_TOKEN_TTL_SECONDS,))
        try:
            conn.execute("DELETE FROM webauthn_setup_sessions WHERE expires_at < ?", (now,))
            conn.execute(
                """DELETE FROM webauthn_setup_sessions
                    WHERE session_id NOT IN (
                        SELECT session_id FROM webauthn_setup_sessions
                         ORDER BY expires_at DESC LIMIT ?)""",
                (MAX_SETUP_SESSIONS,),
            )
        except sqlite3.OperationalError:
            pass  # webauthn tables are created later, by webauthn_login on import
        conn.execute(_CLIENT_RETENTION_SQL)


def _scopes_to_str(scopes: list[str] | None) -> str:
    return " ".join(scopes or [])


def _scopes_from_str(s: str) -> list[str]:
    return s.split() if s else []


class ShellAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, base_url: str, login_path: str = "/login"):
        self._base_url = base_url.rstrip("/")
        self._login_path = login_path
        # Tokens are minted for a specific resource; anything issued for a
        # different one must not be accepted here.
        self._resource = _canon(f"{self._base_url}/mcp")
        # (bucket, ip) -> list of failed-attempt timestamps. Bucketed because a
        # single counter means visiting the passkey setup page a few times
        # exhausts the budget for signing in, locking the operator out of their
        # own server without anything having gone wrong.
        self._failed_attempts: dict[tuple[str, str], list[float]] = {}

    # ---- clients (DCR) ----

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with _connect() as conn:
            row = conn.execute("SELECT data FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        if row is None:
            return None
        return OAuthClientInformationFull.model_validate_json(row["data"])

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not ALLOWED_REDIRECT_URIS:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description=(
                    "This server does not accept client registrations. Set "
                    "MCP_ALLOWED_REDIRECT_URIS to the callback URLs you trust."
                ),
            )
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="At least one redirect_uri is required.",
            )
        for uri in uris:
            if not redirect_uri_allowed(uri):
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=f"redirect_uri {uri} is not on this server's allowlist.",
                )

        with _lock, _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO clients (client_id, data) VALUES (?, ?)",
                (client_info.client_id, client_info.model_dump_json()),
            )
            conn.execute(_CLIENT_RETENTION_SQL)
        _purge_expired()

    # ---- authorize: hand off to our own /login page ----

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        # If the client didn't explicitly request scopes, fall back to the scope
        # it registered with (set to our one "shell" scope via default_scopes),
        # rather than silently granting an empty-scope token.
        scopes = params.scopes or _scopes_from_str(client.scope or "")

        # Checked again here, not just at registration: a client row may predate
        # the allowlist, or have been registered while it was unset.
        if not redirect_uri_allowed(params.redirect_uri):
            raise AuthorizeError(
                error="invalid_request",
                error_description="redirect_uri is not on this server's allowlist.",
            )

        _purge_expired()
        session_id = secrets.token_urlsafe(24)
        with _lock, _connect() as conn:
            conn.execute(
                """INSERT INTO login_sessions
                   (session_id, client_id, state, scopes, code_challenge, redirect_uri,
                    redirect_uri_explicit, resource, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    client.client_id,
                    params.state,
                    _scopes_to_str(scopes),
                    params.code_challenge,
                    str(params.redirect_uri),
                    1 if params.redirect_uri_provided_explicitly else 0,
                    params.resource,
                    time.time() + LOGIN_SESSION_TTL_SECONDS,
                ),
            )
        return f"{self._login_path}?session={session_id}"

    # ---- login: called by the custom /login route in server.py, not by the SDK ----

    def _client_ip_blocked(self, ip: str, bucket: str = "login") -> bool:
        key = (bucket, ip)
        cutoff = time.time() - LOGIN_WINDOW_SECONDS
        attempts = [t for t in self._failed_attempts.get(key, []) if t > cutoff]
        self._failed_attempts[key] = attempts
        return len(attempts) >= LOGIN_MAX_ATTEMPTS

    def _record_failed_attempt(self, ip: str, bucket: str = "login") -> None:
        self._failed_attempts.setdefault((bucket, ip), []).append(time.time())

    def get_login_session(self, session_id: str) -> sqlite3.Row | None:
        with _connect() as conn:
            row = conn.execute(
                "SELECT * FROM login_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None or row["expires_at"] < time.time():
            return None
        return row

    def is_blocked(self, ip: str, bucket: str = "login") -> bool:
        return self._client_ip_blocked(ip, bucket)

    def get_login_context(self, session_id: str) -> dict | None:
        """Who is asking, for display on the login page. Authenticating without
        being shown this is what lets an attacker's authorize link pass for
        your own."""
        row = self.get_login_session(session_id)
        if row is None:
            return None
        name = None
        with _connect() as conn:
            crow = conn.execute(
                "SELECT data FROM clients WHERE client_id = ?", (row["client_id"],)
            ).fetchone()
        if crow is not None:
            try:
                name = OAuthClientInformationFull.model_validate_json(crow["data"]).client_name
            except Exception:
                name = None
        return {
            "client_id": row["client_id"],
            "client_name": name or "(unnamed client)",
            "redirect_uri": row["redirect_uri"],
            "scopes": row["scopes"],
        }

    def get_challenge(self, session_id: str) -> str | None:
        """Returns the nonce to be signed for this session, minting one on first call
        so repeated page loads show the same challenge the user is meant to sign."""
        row = self.get_login_session(session_id)
        if row is None:
            return None
        if row["nonce"]:
            return row["nonce"]
        nonce = secrets.token_urlsafe(24)
        with _lock, _connect() as conn:
            conn.execute(
                "UPDATE login_sessions SET nonce = ? WHERE session_id = ?", (nonce, session_id)
            )
        return nonce

    def _verify_ssh_signature(
        self, nonce: str, signature_text: str, namespace: str = SIGNATURE_NAMESPACE
    ) -> bool:
        signature_text = signature_text.strip()
        if not signature_text.startswith("-----BEGIN SSH SIGNATURE-----"):
            return False
        with tempfile.TemporaryDirectory() as td:
            sig_path = Path(td) / "nonce.sig"
            sig_path.write_text(signature_text + "\n")
            try:
                result = subprocess.run(
                    [
                        "ssh-keygen", "-Y", "verify",
                        "-f", str(ALLOWED_SIGNERS_PATH),
                        "-I", SIGNATURE_PRINCIPAL,
                        "-n", namespace,
                        "-s", str(sig_path),
                    ],
                    input=(nonce + "\n").encode(),
                    capture_output=True,
                    timeout=10,
                )
            except (subprocess.SubprocessError, OSError):
                return False
        return result.returncode == 0

    def verify_signature(self, ip: str, session_id: str, signature_text: str) -> bool:
        """Returns True if signature_text is a valid signature over this session's
        nonce from a key listed in ALLOWED_SIGNERS_PATH. Enforces rate limiting."""
        if self._client_ip_blocked(ip):
            return False
        row = self.get_login_session(session_id)
        if row is None or not row["nonce"]:
            return False
        ok = self._verify_ssh_signature(row["nonce"], signature_text)
        if not ok:
            self._record_failed_attempt(ip)
        return ok

    def verify_raw_signature(self, nonce: str, signature_text: str, namespace: str) -> bool:
        """Verify an SSH signature over `nonce` in the given signing namespace,
        without touching login_sessions. Used by the WebAuthn setup ceremony,
        which needs the same proof-of-key-possession step as login but isn't
        tied to an OAuth authorization request. Rate limiting is the caller's
        responsibility (is_blocked / record_failed_attempt), same as verify_signature."""
        return self._verify_ssh_signature(nonce, signature_text, namespace=namespace)

    def record_failed_attempt(self, ip: str, bucket: str = "login") -> None:
        self._record_failed_attempt(ip, bucket)

    def complete_login(self, session_id: str) -> str | None:
        """Password verified: mint an auth code, consume the session, return the
        redirect URL (with code+state) to send the browser to, or None if the
        session is missing/expired."""
        row = self.get_login_session(session_id)
        if row is None:
            return None
        # Checked once more at the last moment. A session opened while the
        # allowlist was wider, or before it was set at all, must not be able to
        # complete against a callback that is no longer permitted.
        if not redirect_uri_allowed(row["redirect_uri"]):
            return None

        code = secrets.token_urlsafe(32)
        with _lock, _connect() as conn:
            conn.execute(
                """INSERT INTO auth_codes
                   (code, client_id, scopes, code_challenge, redirect_uri,
                    redirect_uri_explicit, resource, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    code,
                    row["client_id"],
                    row["scopes"],
                    row["code_challenge"],
                    row["redirect_uri"],
                    row["redirect_uri_explicit"],
                    row["resource"],
                    time.time() + AUTH_CODE_TTL_SECONDS,
                ),
            )
            conn.execute("DELETE FROM login_sessions WHERE session_id = ?", (session_id,))

        from mcp.server.auth.provider import construct_redirect_uri

        return construct_redirect_uri(row["redirect_uri"], code=code, state=row["state"])

    # ---- authorization code -> tokens ----

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        with _connect() as conn:
            row = conn.execute(
                "SELECT * FROM auth_codes WHERE code = ?", (authorization_code,)
            ).fetchone()
        if row is None:
            return None
        return AuthorizationCode(
            code=row["code"],
            scopes=_scopes_from_str(row["scopes"]),
            expires_at=row["expires_at"],
            client_id=row["client_id"],
            code_challenge=row["code_challenge"],
            redirect_uri=AnyUrl(row["redirect_uri"]),
            redirect_uri_provided_explicitly=bool(row["redirect_uri_explicit"]),
            resource=row["resource"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        # One grant id ties every token descended from this login together, so a
        # single revocation can end all of them.
        grant_id = secrets.token_urlsafe(16)
        resource = _canon(getattr(authorization_code, "resource", None))
        expires_at = int(time.time() + ACCESS_TOKEN_TTL_SECONDS)
        refresh_expires_at = int(time.time() + REFRESH_TOKEN_TTL_SECONDS)
        scopes = _scopes_to_str(authorization_code.scopes)

        with _lock, _connect() as conn:
            conn.execute(
                "INSERT INTO access_tokens (token, client_id, scopes, expires_at, grant_id, resource)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (_hash_token(access_token), authorization_code.client_id, scopes, expires_at, grant_id, resource),
            )
            conn.execute(
                "INSERT INTO refresh_tokens (token, client_id, scopes, expires_at, grant_id, resource)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (_hash_token(refresh_token), authorization_code.client_id, scopes, refresh_expires_at, grant_id, resource),
            )
            conn.execute("DELETE FROM auth_codes WHERE code = ?", (authorization_code.code,))

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            refresh_token=refresh_token,
            scope=scopes,
        )

    # ---- refresh ----

    def _kill_grant(self, grant_id: str) -> None:
        with _lock, _connect() as conn:
            conn.execute("DELETE FROM access_tokens WHERE grant_id = ?", (grant_id,))
            conn.execute("DELETE FROM refresh_tokens WHERE grant_id = ?", (grant_id,))

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        hashed = _hash_token(refresh_token)
        with _connect() as conn:
            row = conn.execute("SELECT * FROM refresh_tokens WHERE token = ?", (hashed,)).fetchone()
            replayed = None
            if row is None:
                replayed = conn.execute(
                    "SELECT grant_id FROM used_refresh_tokens WHERE token = ?", (hashed,)
                ).fetchone()
        if row is None:
            # A refresh token that was already rotated is being presented again.
            # Either it leaked or two parties hold it; either way the grant can
            # no longer be trusted, so end all of it rather than just failing.
            if replayed is not None and replayed["grant_id"]:
                self._kill_grant(replayed["grant_id"])
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=row["client_id"],
            scopes=_scopes_from_str(row["scopes"]),
            expires_at=row["expires_at"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        new_access_token = secrets.token_urlsafe(32)
        new_refresh_token = secrets.token_urlsafe(32)
        expires_at = int(time.time() + ACCESS_TOKEN_TTL_SECONDS)
        refresh_expires_at = int(time.time() + REFRESH_TOKEN_TTL_SECONDS)
        old_hash = _hash_token(refresh_token.token)

        with _lock, _connect() as conn:
            prev = conn.execute(
                "SELECT grant_id, resource FROM refresh_tokens WHERE token = ?", (old_hash,)
            ).fetchone()
            grant_id = prev["grant_id"] if prev is not None else None
            resource = prev["resource"] if prev is not None else None
            if not grant_id:
                grant_id = secrets.token_urlsafe(16)  # unreachable; see _init_db

            # The access token issued alongside the refresh token being replaced
            # does not survive rotation; otherwise revoking the refresh token
            # leaves a working access token behind for the rest of its lifetime.
            conn.execute("DELETE FROM access_tokens WHERE grant_id = ?", (grant_id,))
            conn.execute(
                "INSERT INTO access_tokens (token, client_id, scopes, expires_at, grant_id, resource)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (_hash_token(new_access_token), refresh_token.client_id, _scopes_to_str(scopes), expires_at, grant_id, resource),
            )
            conn.execute(
                "INSERT INTO refresh_tokens (token, client_id, scopes, expires_at, grant_id, resource)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (_hash_token(new_refresh_token), refresh_token.client_id, _scopes_to_str(scopes), refresh_expires_at, grant_id, resource),
            )
            # Rotate, and remember the old token so a replay is detectable.
            conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (old_hash,))
            conn.execute(
                "INSERT OR REPLACE INTO used_refresh_tokens (token, grant_id, used_at) VALUES (?, ?, ?)",
                (old_hash, grant_id, time.time()),
            )

        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            refresh_token=new_refresh_token,
            scope=_scopes_to_str(scopes),
        )

    # ---- resource-server-side token verification ----

    async def load_access_token(self, token: str) -> AccessToken | None:
        with _connect() as conn:
            row = conn.execute(
                "SELECT * FROM access_tokens WHERE token = ?", (_hash_token(token),)
            ).fetchone()
        if row is None:
            return None
        if row["expires_at"] and row["expires_at"] < time.time():
            return None
        # Tokens minted for some other resource are not ours to accept. Rows
        # written before resource tracking have NULL here and stay valid.
        if row["resource"] and self._resource and row["resource"] != self._resource:
            return None
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=_scopes_from_str(row["scopes"]),
            expires_at=row["expires_at"],
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoking any token from a grant revokes the whole grant. Revoking one
        token and leaving its siblings usable is not what a user asking to
        disconnect a client means."""
        hashed = _hash_token(token.token)
        with _lock, _connect() as conn:
            row = conn.execute(
                "SELECT grant_id FROM access_tokens WHERE token = ?"
                " UNION SELECT grant_id FROM refresh_tokens WHERE token = ?",
                (hashed, hashed),
            ).fetchone()
            grant_id = row["grant_id"] if row is not None else None
            # Every token carries a grant since the migration in _init_db, so the
            # single-token branch should be unreachable. It stays as a guard: if
            # a grant is ever missing, delete the token rather than nothing.
            if grant_id:
                conn.execute("DELETE FROM access_tokens WHERE grant_id = ?", (grant_id,))
                conn.execute("DELETE FROM refresh_tokens WHERE grant_id = ?", (grant_id,))
                conn.execute("DELETE FROM used_refresh_tokens WHERE grant_id = ?", (grant_id,))
            else:
                conn.execute("DELETE FROM access_tokens WHERE token = ?", (hashed,))
                conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (hashed,))
