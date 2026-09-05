# Audit handoff

Written for a reviewer picking this up cold. It says what changed, what was
checked, and more usefully what was not. Current as of commit `1db2790`.

## What this program is

An MCP server exposing one tool that runs a shell command on the host and
returns the exit code, stdout and stderr. It is reached over the public
internet, so almost all of the code is the authentication around that one
tool rather than the tool itself.

The security boundary is the auth path and nothing else. A valid token is a
shell. There is no second line of defence inside the application.

## Deployment it was written for

Single operator, one client. The reference deployment is a Debian VM with the
server bound to loopback and a tunnel terminating TLS in front of it. Shell
access at the privilege of the service account is the intended feature, not a
flaw to be designed away.

Anything an auditor concludes about that deployment specifically (proxy rules,
file permissions, sudo configuration, package versions) cannot be determined
from this source tree.

## History

`d3c2f44` was the first public commit. An external review of it raised seven
findings. Four commits followed:

| Commit | Scope |
| --- | --- |
| `74d196a` | The seven findings |
| `f429b9c` | Commands blocked the event loop, found while testing the above |
| `b79daa1` | Configuration loading and first-run setup |
| `1db2790` | Wording of the setup prompts, no behaviour change |

## What changed, by finding

**1. Authorization was missing.** Dynamic client registration is open by
protocol and the login page never named the requesting client, so an attacker
could register a client with their own callback, send the operator its
authorize link, and receive the code when the operator signed in on the real
domain. Holding the signing key proves who you are, never who you are granting
to.

Registrable callbacks are now pinned to `MCP_ALLOWED_REDIRECT_PREFIXES`,
enforced in `register_client` and again in `authorize` so a client row predating
the allowlist cannot be used. Unset means every registration is refused. The
login page shows the client name, client id, callback and scope before anything
is signed.

**2. Commands run as the service account.** Unchanged in substance. The account
running the server owns `data/store.sqlite3`, `data/allowed_signers` and the
code, so a command can rewrite what constrains it and can outlive a revoked
token. `MCP_EXEC_USER` will run commands through `sudo -n -u`, and
`mcp-shell.service.example` carries systemd hardening, but both are opt in and
the reference deployment has neither enabled. Treat this as open.

**3. Request size limits and unbounded public state.** The old checks read
`Content-Length`, which a chunked request simply omits, and the body was then
read whole. `_read_body_limited` now counts bytes as they arrive. Expired rows
are swept on a throttle, pending passkey setup sessions are capped, and the
setup endpoint shares the login rate limiter.

**4. Client retention evicted pending clients.** Retention kept clients holding
tokens plus the three most recent without. A client part way through
authorizing holds neither, so three registrations evicted it. The predicate now
also protects clients with an open login session or an unredeemed code.

**5. Tokens were not bound to a resource.** The `resource` parameter reached the
authorization code and was dropped at token issuance. It is now stored on both
token tables and checked in `load_access_token`. Rows written before the
migration have NULL and are accepted, so upgrading does not invalidate a live
session.

**6. Revocation was partial.** Tokens descending from one login now share a
`grant_id`. Revoking any revokes all. Rotation deletes the access token it
replaces. A replayed refresh token is treated as compromise and ends the grant.
The SDK's revocation handler declares `client_secret` without a default and so
rejects public clients that correctly omit it; `server.py` gives the field a
default when the installed SDK still has that bug.

**7. Execution and audit.** Output is drained under a byte ceiling instead of
buffered whole. Timeout kills the process group rather than the direct child.
Cancelling the request kills the child. Commands are audited before execution
as well as after. `MCP_REQUIRE_AUDIT_KEY=1` refuses to start rather than fall
back to plaintext lines.

**Found separately.** The MCP SDK calls a synchronous tool function directly on
the event loop, so a running command blocked every other request, auth
included, for up to the full timeout. `run_command` is async and offloads to a
worker thread under its own capacity limiter.

## What was verified, and how

Against a throwaway instance on a spare port with its own database and a
disposable key, not against the live deployment:

- Registration refused for a callback outside the allowlist, accepted inside it
- Login page contains the client name, callback and the words granting access
- Authorization code exchange, PKCE, and `initialize` against `/mcp`
- Rotation invalidates the previous access token
- Replaying a rotated refresh token kills the grant, successor included
- Revoking a refresh token kills its sibling access token, with no
  `client_secret` sent
- A token issued for a different resource is refused
- A chunked body over the limit with no `Content-Length` returns 413
- A client mid-authorization survives five further registrations
- Expired setup sessions are swept
- Timeout leaves no surviving process; cancellation leaves no orphan
- 60 MB of output returns bounded in about a second
- Unrelated requests answered in roughly 35 ms during a 10 second command
- Two 6 second commands completed in 6.2 seconds wall
- Twelve concurrent commands produced 24 well formed audit lines
- First-run setup output alone boots a server with the allowlist active
- A generated audit key round trips through `decrypt_log.py`

## What was not verified

Worth attacking, because nothing here has been checked:

- **WebAuthn end to end.** No browser was involved. Registration and
  authentication were exercised only through the setup signature path and
  `test_webauthn_setup.py`. Origin, RP id, challenge and sign count handling
  were read, not executed.
- **The MCP SDK itself.** Treated as trusted. PKCE verification, code reuse,
  metadata endpoints and client authentication all live there.
- **Concurrency of the storage layer.** Commands now run in worker threads
  while requests are served concurrently. The tool thread touches no database,
  and writes are guarded by a process-wide lock, but this reasoning has not been
  stress tested.
- **The rate limiter.** In-memory, per process, keyed on an IP taken from
  request headers behind a proxy. Not tested for spoofing or for behaviour
  across a restart.
- **Anything about the live host.** Proxy configuration, file modes, sudo
  rules, installed versions.
- **The tests themselves are not in the repo.** They were ad hoc scripts
  against a scratch instance. There is no committed suite to re-run, which is
  a real gap for a project asking to be trusted.

## Known open items

1. Finding 2 above. The largest remaining gap by consequence.
2. Commands inherit the server's environment, including every `MCP_*` setting.
   No secrets live there and any command could read `.env` anyway, so this is
   cosmetic today. It stops being cosmetic if `MCP_EXEC_USER` is enabled, since
   the point of that account is to know less than the service does.
3. Audit lines are written to a file the service account can delete or replace.
   Encryption prevents reading, not destruction.
4. `MAX_TOKENLESS_CLIENTS`, the purge interval and the rate limit window are
   constants, not settings.
5. No automated test suite in the repository.

## Suggested lines of attack

More useful than re-deriving the above:

- Can a client registered while `MCP_ALLOWED_REDIRECT_PREFIXES` was unset still
  complete an authorization? The authorize-time check is meant to close this.
- Does prefix matching on `redirect_uri` admit anything it should not?
  `https://claude.ai/api/mcp/auth_callback` as a prefix, and what a crafted
  URL can do with it.
- Is the grant-wide revocation reachable for every token shape, including one
  issued before the migration where `grant_id` is NULL?
- Can the refresh replay detection be turned into a denial of service against
  the legitimate client?
- Does `_read_body_limited` interact badly with any transfer encoding or with
  the proxy in front?
- Is the per-IP rate limiter meaningful given the IP is derived from headers?
- WebAuthn, all of it.

## Reproducing the test environment

```sh
mkdir /tmp/t && cd /tmp/t && cp /path/to/repo/*.py .
ssh-keygen -q -t ed25519 -N '' -f testkey
mkdir data && echo "test-principal $(cat testkey.pub)" > data/allowed_signers
export MCP_BASE_URL=http://127.0.0.1:8899 HOST=127.0.0.1 PORT=8899
export MCP_SIGNATURE_PRINCIPAL=test-principal
export MCP_ALLOWED_REDIRECT_PREFIXES=https://good.example.com/cb
python server.py
```

`http` on loopback is accepted; setup refuses it for a public host.
