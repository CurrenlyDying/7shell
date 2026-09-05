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

from pydantic import AnyUrl

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
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

# Login rate limiting: per source IP, max attempts within the window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60

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
        # Migration for DBs created before the nonce column existed.
        try:
            conn.execute("ALTER TABLE login_sessions ADD COLUMN nonce TEXT")
        except sqlite3.OperationalError:
            pass


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


def _scopes_to_str(scopes: list[str] | None) -> str:
    return " ".join(scopes or [])


def _scopes_from_str(s: str) -> list[str]:
    return s.split() if s else []


class ShellAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, base_url: str, login_path: str = "/login"):
        self._base_url = base_url.rstrip("/")
        self._login_path = login_path
        # ip -> list of failed-attempt timestamps
        self._failed_attempts: dict[str, list[float]] = {}

    # ---- clients (DCR) ----

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with _connect() as conn:
            row = conn.execute("SELECT data FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        if row is None:
            return None
        return OAuthClientInformationFull.model_validate_json(row["data"])

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        with _lock, _connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO clients (client_id, data) VALUES (?, ?)",
                (client_info.client_id, client_info.model_dump_json()),
            )
            # Open (unauthenticated) DCR lets anyone reaching the endpoint create
            # a client row. Registration alone grants nothing (a token still
            # requires the SSH-signature login), but junk rows would grow without
            # bound. Keep every client that holds tokens (the real connector),
            # plus only the 3 most recent token-less ones; drop the rest. Since
            # token-bearing clients are never evicted, an anonymous flood cannot
            # push the live client out.
            conn.execute(
                """
                DELETE FROM clients
                 WHERE client_id NOT IN (SELECT client_id FROM access_tokens)
                   AND client_id NOT IN (SELECT client_id FROM refresh_tokens)
                   AND client_id NOT IN (
                       SELECT client_id FROM clients
                        WHERE client_id NOT IN (SELECT client_id FROM access_tokens)
                          AND client_id NOT IN (SELECT client_id FROM refresh_tokens)
                        ORDER BY rowid DESC
                        LIMIT 3
                   )
                """
            )

    # ---- authorize: hand off to our own /login page ----

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        # If the client didn't explicitly request scopes, fall back to the scope
        # it registered with (set to our one "shell" scope via default_scopes),
        # rather than silently granting an empty-scope token.
        scopes = params.scopes or _scopes_from_str(client.scope or "")

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

    def _client_ip_blocked(self, ip: str) -> bool:
        attempts = self._failed_attempts.get(ip, [])
        cutoff = time.time() - LOGIN_WINDOW_SECONDS
        attempts = [t for t in attempts if t > cutoff]
        self._failed_attempts[ip] = attempts
        return len(attempts) >= LOGIN_MAX_ATTEMPTS

    def _record_failed_attempt(self, ip: str) -> None:
        self._failed_attempts.setdefault(ip, []).append(time.time())

    def get_login_session(self, session_id: str) -> sqlite3.Row | None:
        with _connect() as conn:
            row = conn.execute(
                "SELECT * FROM login_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        if row is None or row["expires_at"] < time.time():
            return None
        return row

    def is_blocked(self, ip: str) -> bool:
        return self._client_ip_blocked(ip)

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

    def record_failed_attempt(self, ip: str) -> None:
        self._record_failed_attempt(ip)

    def complete_login(self, session_id: str) -> str | None:
        """Password verified: mint an auth code, consume the session, return the
        redirect URL (with code+state) to send the browser to, or None if the
        session is missing/expired."""
        row = self.get_login_session(session_id)
        if row is None:
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
        expires_at = int(time.time() + ACCESS_TOKEN_TTL_SECONDS)
        refresh_expires_at = int(time.time() + REFRESH_TOKEN_TTL_SECONDS)

        with _lock, _connect() as conn:
            conn.execute(
                "INSERT INTO access_tokens (token, client_id, scopes, expires_at) VALUES (?, ?, ?, ?)",
                (_hash_token(access_token), authorization_code.client_id, _scopes_to_str(authorization_code.scopes), expires_at),
            )
            conn.execute(
                "INSERT INTO refresh_tokens (token, client_id, scopes, expires_at) VALUES (?, ?, ?, ?)",
                (_hash_token(refresh_token), authorization_code.client_id, _scopes_to_str(authorization_code.scopes), refresh_expires_at),
            )
            conn.execute("DELETE FROM auth_codes WHERE code = ?", (authorization_code.code,))

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            refresh_token=refresh_token,
            scope=_scopes_to_str(authorization_code.scopes),
        )

    # ---- refresh ----

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        with _connect() as conn:
            row = conn.execute(
                "SELECT * FROM refresh_tokens WHERE token = ?", (_hash_token(refresh_token),)
            ).fetchone()
        if row is None:
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

        with _lock, _connect() as conn:
            conn.execute(
                "INSERT INTO access_tokens (token, client_id, scopes, expires_at) VALUES (?, ?, ?, ?)",
                (_hash_token(new_access_token), refresh_token.client_id, _scopes_to_str(scopes), expires_at),
            )
            conn.execute(
                "INSERT INTO refresh_tokens (token, client_id, scopes, expires_at) VALUES (?, ?, ?, ?)",
                (_hash_token(new_refresh_token), refresh_token.client_id, _scopes_to_str(scopes), refresh_expires_at),
            )
            # Rotate: the old refresh token is invalidated immediately.
            conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (_hash_token(refresh_token.token),))

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
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=_scopes_from_str(row["scopes"]),
            expires_at=row["expires_at"],
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        with _lock, _connect() as conn:
            conn.execute("DELETE FROM access_tokens WHERE token = ?", (_hash_token(token.token),))
            conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (_hash_token(token.token),))
