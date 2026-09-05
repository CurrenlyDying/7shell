"""Configuration, and the interactive setup that produces it.

Every setting is an environment variable. A `.env` file next to this module is
read into the environment when this module is imported, so the same file works
whether the server is started by systemd (which reads it via EnvironmentFile) or
by hand. Variables already present in the environment always win over the file,
so a single setting can be overridden for one run without editing anything.

If the required settings are missing and the server is attached to a terminal,
`ensure_configured()` walks the operator through them and writes the file. With
no terminal it fails with an explanation instead, because a service that blocks
on stdin at boot hangs forever rather than telling anyone why.
"""

import base64
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

ENV_PATH = Path(__file__).parent / ".env"
DATA_DIR = Path(__file__).parent / "data"
ALLOWED_SIGNERS = DATA_DIR / "allowed_signers"
RECIPIENT_PUB = DATA_DIR / "log_recipient.pub"

REQUIRED = ("MCP_BASE_URL", "MCP_ALLOWED_REDIRECT_PREFIXES")

CLAUDE_CALLBACKS = "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback"


def load_env_file(path: Path = ENV_PATH) -> None:
    """Merge KEY=value lines from `path` into os.environ without overriding
    anything already set. Deliberately not a shell parser: no expansion, no
    substitution, no `export`."""
    try:
        text = path.read_text()
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _ask(prompt: str, default: str = "", required: bool = False) -> str:
    while True:
        shown = f" [{default}]" if default else ""
        answer = input(f"{prompt}{shown}: ").strip() or default
        if answer or not required:
            return answer
        print("  Required.")


def _yes(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    answer = input(f"{prompt} [{d}]: ").strip().lower()
    return default if not answer else answer.startswith("y")


def _write_env(values: dict[str, str]) -> None:
    lines = ["# Written by first-run setup. Safe to edit; see .env.example.", ""]
    lines += [f"{k}={v}" for k, v in values.items() if v != ""]
    ENV_PATH.write_text("\n".join(lines) + "\n")
    ENV_PATH.chmod(0o600)


def _setup_allowed_signers(principal: str) -> None:
    if ALLOWED_SIGNERS.exists() and ALLOWED_SIGNERS.read_text().strip():
        print(f"\n{ALLOWED_SIGNERS} already has entries, leaving it alone.")
        return
    print(
        "\nYour SSH public key is what lets you log in. Paste the contents of a "
        "\n.pub file (for example ~/.ssh/id_ed25519.pub), or leave blank to do it later."
    )
    key = _ask("Public key")
    if not key:
        print(f"  Skipped. Add a line to {ALLOWED_SIGNERS} before you can sign in:")
        print(f"    {principal} ssh-ed25519 AAAA...")
        return
    parts = key.split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        print("  That does not look like an SSH public key. Skipping.")
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # The first field has to be the principal the server verifies against, which
    # is the mismatch people hit when writing this file by hand.
    ALLOWED_SIGNERS.write_text(f"{principal} {parts[0]} {parts[1]}\n")
    ALLOWED_SIGNERS.chmod(0o600)
    print(f"  Wrote {ALLOWED_SIGNERS} with principal '{principal}'.")


def _setup_audit_key() -> None:
    if RECIPIENT_PUB.exists():
        print(f"\n{RECIPIENT_PUB} already exists, leaving it alone.")
        return
    print(
        "\nThe audit log can be encrypted to a key whose private half you keep off"
        "\nthis machine, so whoever takes the box cannot read the command history."
    )
    if not _yes("Generate an audit key pair now?"):
        print("  Skipped. Audit lines will be written in plaintext until you install one.")
        return
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

    priv = X25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RECIPIENT_PUB.write_text(pub_b64 + "\n")
    print(f"  Public half written to {RECIPIENT_PUB}.")
    print("\n  " + "=" * 68)
    print("  PRIVATE KEY, SHOWN ONCE. Copy it somewhere off this machine now.")
    print("  Without it the audit log cannot be read. It is deliberately not")
    print("  saved here, since a copy on this box defeats the point.")
    print("  " + "=" * 68)
    print(f"\n    {priv_b64}\n")
    print("  Read the log later with:  python decrypt_log.py <that-key-in-a-file>")
    input("  Press Enter once you have stored it. ")


def run_setup() -> dict[str, str]:
    print("\n  mcp-shell-server setup")
    print("  " + "-" * 22)
    print("  Answers are written to .env. Re-run any time with --setup.\n")

    base_url = ""
    while not base_url:
        base_url = _ask("Public URL this server will be reached at", required=True)
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            print("  Needs to be a full URL, for example https://mcp.example.com")
            base_url = ""
        elif parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
            print("  Refusing http for a public host: passkeys and OAuth both need https.")
            base_url = ""

    print(
        "\nOnly clients whose callback starts with one of these may register."
        "\nWithout it anyone can register a client pointing at their own callback,"
        "\nsend you its login link, and receive the code when you sign in."
    )
    prefixes = _ask("Allowed callback prefixes (comma separated)", CLAUDE_CALLBACKS, required=True)

    print("\nThe principal is a label tying your SSH key to this server. Any string,")
    print("as long as it matches the first field in data/allowed_signers.")
    principal = _ask("Signing principal", "mcp-user")

    host = _ask("\nBind address (keep on loopback behind a tunnel)", "127.0.0.1")
    port = _ask("Port", "8811")

    print("\nCommands can run as a different, less privileged account, so that a")
    print("command cannot rewrite this server's own auth database or code. Needs a")
    print("passwordless sudoers rule for that account. Leave blank to run commands")
    print("as the same user as the server.")
    exec_user = _ask("Run commands as user")

    values = {
        "MCP_BASE_URL": base_url.rstrip("/"),
        "HOST": host,
        "PORT": port,
        "MCP_ALLOWED_REDIRECT_PREFIXES": prefixes,
        "MCP_SIGNATURE_PRINCIPAL": principal,
        "MCP_WEBAUTHN_USER_ID": principal,
        "MCP_WEBAUTHN_USER_NAME": principal,
        "MCP_EXEC_USER": exec_user,
    }
    _write_env(values)
    print(f"\nWrote {ENV_PATH} (owner-readable only).")

    _setup_allowed_signers(principal)
    _setup_audit_key()

    print("\nSetup complete. Starting the server.\n")
    os.environ.update({k: v for k, v in values.items() if v != ""})
    return values


def ensure_configured(force: bool = False) -> None:
    load_env_file()
    missing = [k for k in REQUIRED if not os.environ.get(k)]
    if not force and not missing:
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise SystemExit(
            "Missing required configuration: " + ", ".join(missing or REQUIRED) + "\n"
            f"No terminal attached, so setup cannot ask for it. Either create {ENV_PATH} "
            "(copy .env.example), or run `python server.py --setup` from a shell."
        )
    run_setup()
