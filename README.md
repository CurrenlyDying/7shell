# mcp-shell-server

A self-hosted [MCP](https://modelcontextprotocol.io) server that gives an MCP
client one tool: run a shell command on the host and get back the exit code,
stdout and stderr.

It is meant to be reached over the public internet through a tunnel or reverse
proxy, so most of the code is not the shell tool (that part is short) but the
authentication and audit machinery around it.

## Read this before you run it

This grants **shell access as the user the service runs as**. Anyone who gets a
valid token gets that shell. Treat the auth path as the whole security boundary,
because it is.

Two things are your responsibility and cannot be fixed in this code:

- **Set `MCP_ALLOWED_REDIRECT_PREFIXES`.** Nothing registers without it, which is
  the intended failure mode.
- **Do not let the shell run as this service's own user.** By default it does,
  which means an authorized command can rewrite the auth database, the trusted
  keys, this code, and the logs, and can outlive any token you revoke. Set
  `MCP_EXEC_USER` to a separate account and use the hardening in
  `mcp-shell.service.example`.

## What it does

- **One tool**, `run_command(command, cwd, timeout_seconds)`, executed via
  `bash -lc`, with a timeout capped server-side.
- **OAuth 2.0 authorization server** built on the MCP SDK's provider interface.
  Bearer tokens are stored only as SHA-256 hashes, so the database never holds a
  usable token.
- **Registration allowlist.** Dynamic client registration is open by protocol.
  On its own that means anyone can register a client with their own callback,
  send you its authorize link, and receive the code when you sign in on your own
  real domain. A signature proves who you are, never who you are granting to, so
  `MCP_ALLOWED_REDIRECT_PREFIXES` pins the callbacks that may register at all,
  checked again at authorize time. Unset means no client can register.
- **Named grants on the login page.** Before you sign anything the page tells you
  which client is asking, where the code will be sent, and that continuing hands
  over shell access.
- **Two login methods** at the authorize step:
  - **SSH signature.** The server issues a challenge; you sign it with
    `ssh-keygen -Y sign` on a device you control and paste the signature back.
    Verified against an `allowed_signers` file.
  - **WebAuthn / passkey**, registered through `/webauthn/setup`.
- **Grant-scoped tokens.** Every token descended from one login shares a grant
  id. Revoking any of them revokes all of them, rotation retires the access token
  it replaces, and replaying an already-rotated refresh token is treated as a
  compromise and ends the grant. Tokens are bound to this server's resource and
  refused elsewhere.
- **Write-only audit log.** Each entry's detail is encrypted to an X25519 public
  key whose private half lives off the box, so a compromise of the host does not
  hand over the command history. `decrypt_log.py` reads it back with the offline
  key. Commands are recorded before they run as well as after. Set
  `MCP_REQUIRE_AUDIT_KEY=1` to refuse to start rather than fall back to plaintext.
- **Bounded execution.** Output is streamed with a hard byte ceiling instead of
  being buffered whole, and a timeout kills the entire process group rather than
  just the direct child. Cancelling the request kills the child too.
- **Commands do not block the server.** The MCP SDK calls a synchronous tool
  function directly on the event loop, so a blocking implementation stops every
  other request, auth included, for as long as the command runs. Execution is
  offloaded to a worker thread under its own capacity limiter
  (`MCP_MAX_CONCURRENT_COMMANDS`, default 8).
- **Bounded public state.** Body size limits are enforced against bytes actually
  received, not a `Content-Length` header that a chunked request simply omits.
  Unauthenticated endpoints are rate limited and expired rows are swept.
- **DNS rebinding protection** left on, with the public hostname explicitly
  allowed so tunnelled requests are not rejected.

## Layout

| File | Purpose |
| --- | --- |
| `server.py` | MCP server, HTTP routes, the `run_command` tool, audit calls |
| `auth_provider.py` | OAuth provider: clients, codes, tokens, SQLite storage |
| `webauthn_login.py` | Passkey registration and authentication |
| `logcrypt.py` | Encrypt-on-append audit logging |
| `decrypt_log.py` | Offline reader for the audit log |
| `test_webauthn_setup.py` | Checks for the WebAuthn setup path |
| `config.py` | Loads `.env`, and the first-run setup that writes it |

## Install

```sh
git clone <this repo> && cd mcp-shell-server
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py
```

The first run has nothing to go on, so it asks. It walks through the public URL,
the callbacks allowed to register, the signing principal, the bind address, and
whether commands should run as a separate user. Then it offers to write your SSH
public key into `data/allowed_signers` with the matching principal, and to
generate an audit key pair, showing the private half once so you can store it off
the machine.

Answers land in `.env`, owner-readable only. Re-run the questions any time with
`.venv/bin/python server.py --setup`, or edit the file directly; `.env.example`
documents every setting including the few setup does not ask about.

Nothing assumes a particular hostname, username, or account name. `.env` is the
whole configuration.

`.env` is read by the server itself and by systemd's `EnvironmentFile`, so the
same file works either way. Real environment variables win over the file, so a
single setting can be overridden for one run without editing anything.

Under systemd there is no terminal to ask at, so a missing configuration exits
with an explanation rather than hanging on a prompt at boot. Run setup once from
a shell first. Install `mcp-shell.service.example` as a unit after editing the
paths and user.

Bind to loopback and put a tunnel or reverse proxy in front for TLS. The server
expects to be reached at `MCP_BASE_URL`.

## Signing a login challenge

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n mcp-login challenge.txt
```

Paste the resulting signature block into the login page.

## License

Unlicense. Public domain, see `LICENSE`.
