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
  just the direct child.
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

## Install

```sh
git clone <this repo> && cd mcp-shell-server
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env      # then edit it
mkdir -p data
```

Everything user-specific lives in `.env`: your public URL, the signing principal,
and the passkey identity. Nothing in the source assumes a particular hostname or
username.

Add the public half of an SSH key to `data/allowed_signers`, in the format
`ssh-keygen -Y verify` expects. The first field must equal
`MCP_SIGNATURE_PRINCIPAL`:

```
mcp-user ssh-ed25519 AAAAC3Nz...
```

Set `MCP_WEBAUTHN_USER_ID` before registering your first passkey. The user id is
written into the credential at registration, so changing it later means
re-registering.

Generate an audit key pair off the box, and install only the public half as
`data/log_recipient.pub`.

Run it directly with `.venv/bin/python server.py`, or install
`mcp-shell.service.example` as a systemd unit after editing the paths and user.

Bind to loopback and put a tunnel or reverse proxy in front for TLS. The server
expects to be reached at `MCP_BASE_URL`.

## Signing a login challenge

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n mcp-login challenge.txt
```

Paste the resulting signature block into the login page.

## License

Unlicense. Public domain, see `LICENSE`.
