# Audit handoff

Written for a reviewer picking this up cold. It says what changed, what was
checked, and more usefully what was not. Current as of the third review pass.

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
| this one | Second review: legacy tokens, setup cap, cancellation race, exact callbacks, service unit, audit enforcement |

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

## Second review, and what changed

A follow-up review confirmed the first round of fixes and found six more. All
six are addressed:

1. **Legacy tokens escaped grant revocation.** Tokens issued before grant
   tracking had `grant_id` NULL, so revoking one deleted only itself. Nothing
   was ever stored that says which of them belonged together, so they cannot be
   repaired. They are deleted at startup instead, permanently, as an invariant:
   no grant, no token. The cost is reconnecting once after upgrading.
2. **The setup-session cap was not enforced where sessions are created.**
   Cleanup ran from OAuth registration and authorize, neither of which an
   anonymous visitor to `/webauthn/setup` touches. The cap now runs inside
   `start_setup`, unthrottled. Separately, the SDK's own routes had no body
   limit at all; a `BodyLimit` ASGI wrapper now sits in front of everything.
3. **Cancellation could race process creation.** Cancelling before the worker
   reached `Popen` killed nothing and the abandoned worker then started the
   command. `_Job` claims the job under a lock, so either cancel kills a running
   process or marks the job dead before one exists.
4. **Prefix matching on callbacks was a trap.** `https://good.example` also
   matched `https://good.example.attacker.invalid/cb`. Matching is now exact.
   The setting is `MCP_ALLOWED_REDIRECT_URIS`; the old name still works, is
   matched exactly, and prints a deprecation notice.
5. **The example unit contradicted itself.** `NoNewPrivileges=yes` blocks the
   setuid transition `sudo` needs, so it cannot coexist with `MCP_EXEC_USER`. It
   is commented out with the tradeoff explained, and the server now probes the
   user switch at startup and refuses to run if it will not work.
6. **Required audit encryption was checked only at startup.** It is now checked
   on every write. If the key disappears while running, `_audit` raises rather
   than writing plaintext, and a command whose start cannot be recorded does not
   run.

Found while writing the tests for the above, not reported by either review:
login and passkey setup shared one rate-limit counter, so a handful of visits to
the setup page locked the operator out of signing in. The counters are now
separate.

## Third review, and what changed

1. **The example unit did not establish a working `MCP_EXEC_USER`.** Reported on
   the basis that several hardening directives implicitly enable
   `NoNewPrivileges`, which blocks the setuid transition sudo needs. Tested
   under real transient units on systemd 257: none of the directives the unit
   shipped enabled it, and sudo worked. Adding `RestrictNamespaces` and
   `SystemCallFilter` did enable it and did break sudo, exactly as described.
   Rather than depend on which version behaves how, the unit now sets
   `NoNewPrivileges=no` explicitly, which overrides the implication. Verified:
   the full hardening set plus an explicit `no` leaves the switch working. The
   comment says to change it to `yes` when `MCP_EXEC_USER` is unused.
2. **Audit encryption had a check-then-use gap.** Availability was checked and
   the key read again inside encryption, so a key removed between the two reads
   passed the check and was written in plaintext. The requirement now lives
   inside `audit_encrypt(require=True)`, which loads the key once.
3. **Oversized chunked requests to SDK routes returned 500, not 413.** The read
   raised through the application and the SDK's error middleware answered first.
   `BodyLimit` now reads the body before dispatch and refuses outright, so the
   answer is 413 either way. Requests without a body are passed straight
   through, since reading from the long-lived event stream would stall it.
4. **The deprecated variable did not survive startup.** The provider accepted
   `MCP_ALLOWED_REDIRECT_PREFIXES` but configuration validation ran first and
   required the new name. It is normalised before validation now.

Also raised: the setup-cap test made 25 requests from one address, so the rate
limiter rejected most and the storage cap was never exercised. The test now
varies the source address per request.

Found while fixing item 3, not reported by any review: replaying the buffered
body and then returning a fabricated disconnect told streaming responses the
client had gone, truncating them mid-stream. Reads after the body now come from
the real transport.

## Tests

`tests/integration_test.py` starts a real server on a spare port with a
throwaway database and a disposable key. It covers the failure cases above, not
just the happy paths, since happy paths are what let the first round through.
27 checks at present.

```sh
python tests/integration_test.py
```

## What is still not verified

- **WebAuthn in a browser.** The follow-up review exercised the cryptographic
  verification with a software credential, which is more than was done here.
  Real authenticator behaviour is still untested.
- **The MCP SDK itself.** Treated as trusted. PKCE, code reuse, metadata
  endpoints and client authentication live there.
- **The rate limiter under a proxy.** In-memory, per process, keyed on an IP
  derived from request headers. Not tested for spoofing or across a restart.
- **Anything about a live host.** Proxy rules, file modes, sudo configuration,
  installed versions.

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
