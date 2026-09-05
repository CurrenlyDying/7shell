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
import textwrap
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


WIDTH = 74


def _rule(char: str = "-") -> None:
    print("  " + char * WIDTH)


def _para(text: str) -> None:
    """Print an explanation wrapped to the terminal.

    A block indented further than the rest is treated as something to type, and
    is printed as written rather than reflowed into a paragraph.
    """
    lines = text.strip("\n").split("\n")
    # In a triple-quoted string the first line carries no indentation, so the
    # baseline comes from the others; otherwise every later paragraph looks
    # indented relative to it and would be mistaken for a block to type.
    rest = [l for l in lines[1:] if l.strip()]
    base = min((len(l) - len(l.lstrip()) for l in rest), default=0)
    if lines and len(lines[0]) - len(lines[0].lstrip()) < base:
        lines[0] = " " * base + lines[0].lstrip()

    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line)
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)

    for block in blocks:
        if min(len(l) - len(l.lstrip()) for l in block) > base:
            for line in block:
                print("      " + line.strip())
        else:
            print(textwrap.fill(
                " ".join(" ".join(block).split()), width=WIDTH,
                initial_indent="  ", subsequent_indent="  ", break_on_hyphens=False,
            ))
        print()


def _heading(step: int, total: int, title: str) -> None:
    print()
    _rule()
    print(f"  Question {step} of {total}: {title}")
    _rule()
    print()


def _ask(prompt: str, default: str = "", required: bool = False) -> str:
    while True:
        hint = f" (press Enter for {default})" if default else ""
        answer = input(f"  > {prompt}{hint}: ").strip() or default
        print()
        if answer or not required:
            return answer
        print("  This one has no sensible default, so it does need an answer.\n")


def _yes(prompt: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    answer = input(f"  > {prompt} [{d}]: ").strip().lower()
    print()
    return default if not answer else answer.startswith("y")


def _write_env(values: dict[str, str]) -> None:
    lines = ["# Written by first-run setup. Safe to edit; see .env.example.", ""]
    lines += [f"{k}={v}" for k, v in values.items() if v != ""]
    ENV_PATH.write_text("\n".join(lines) + "\n")
    ENV_PATH.chmod(0o600)


def _find_public_keys() -> list[Path]:
    try:
        return sorted(p for p in (Path.home() / ".ssh").glob("*.pub") if p.is_file())
    except OSError:
        return []


def _setup_allowed_signers(principal: str) -> None:
    _heading(7, 7, "Your SSH key")
    if ALLOWED_SIGNERS.exists() and ALLOWED_SIGNERS.read_text().strip():
        _para(f"You already have keys listed in {ALLOWED_SIGNERS}, so this step is skipped.")
        return
    _para(
        """An SSH key comes in two halves. The private half stays on your own
        device and never leaves it. The public half is safe to hand out, and
        that is the one this server needs.

        Signing in works like this: the server shows you a random code, you
        sign that code with your private half, and the server checks the
        signature against the public half. Nobody can fake it without your
        device."""
    )
    keys = _find_public_keys()
    chosen = ""
    if keys:
        _para("Public keys already on this machine:")
        for i, k in enumerate(keys, 1):
            print(f"    {i}. {k.name}")
        print()
        _para(
            "Type a number to use one of those. Or paste a public key from "
            "another device, which is the better option if this server is not "
            "where you normally sit. Or press Enter to skip for now."
        )
        answer = _ask("Number, or a pasted key")
        if answer.isdigit() and 1 <= int(answer) <= len(keys):
            chosen = keys[int(answer) - 1].read_text().strip()
            print(f"  Using {keys[int(answer) - 1].name}.\n")
        else:
            chosen = answer
    else:
        _para(
            """No public keys found in your .ssh folder. Paste one from the
            device you will sign in from, or press Enter to skip.

            If you have never made one, run this on that device and paste what
            the second command prints:

                ssh-keygen -t ed25519
                cat ~/.ssh/id_ed25519.pub"""
        )
        chosen = _ask("Public key")

    if not chosen:
        _para(
            f"""Skipped. You cannot sign in until a key is listed, so before you
            use this server, put a line like this in {ALLOWED_SIGNERS}:

                {principal} ssh-ed25519 AAAAC3Nz...

            The first word has to be exactly '{principal}'."""
        )
        return
    parts = chosen.split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        _para(
            "That does not look like an SSH public key. A real one starts with "
            "'ssh-ed25519' or similar. Skipping this step; you can add it later."
        )
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # The first field has to be the principal the server verifies against, which
    # is the mismatch people hit when writing this file by hand.
    ALLOWED_SIGNERS.write_text(f"{principal} {parts[0]} {parts[1]}\n")
    ALLOWED_SIGNERS.chmod(0o600)
    _para(f"Saved to {ALLOWED_SIGNERS}, labelled '{principal}'. That label matches "
          "your setting, so signing in will work.")


def _setup_audit_key() -> None:
    print()
    _rule()
    print("  One last offer: an unreadable command log")
    _rule()
    print()
    if RECIPIENT_PUB.exists():
        _para(f"You already have a key at {RECIPIENT_PUB}, so this step is skipped.")
        return
    _para(
        """This server writes down every command it runs. That log is useful to
        you and useful to anyone who breaks in, so it can be scrambled as it is
        written, using a key that only unscrambles with a second key you keep
        somewhere else.

        The result is that this machine can add to the log but cannot read it
        back. Neither can anyone who steals it.

        The catch: if you lose the key you keep elsewhere, the log stays
        unreadable to you too. Say no and the log is written in plain text,
        which is fine if that suits you better."""
    )
    if not _yes("Scramble the command log?"):
        _para("Fine. The log will be readable plain text at audit.log.")
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
    print()
    _rule("=")
    print("  YOUR KEY, SHOWN ONCE AND NEVER AGAIN")
    _rule("=")
    print()
    print(f"      {priv_b64}")
    print()
    _para(
        """Copy that somewhere off this machine right now. A password manager, a
        note on your phone, anywhere that is not this server. It is not saved
        here on purpose, because a copy sitting next to the log would defeat
        the whole idea.

        When you want to read the log later, put that key in a file and run:

            python decrypt_log.py thatfile audit.log"""
    )
    input("  Press Enter once you have stored it somewhere safe. ")
    print()


def run_setup() -> dict[str, str]:
    total = 7
    print()
    _rule("=")
    print("  mcp-shell-server: first run")
    _rule("=")
    print()
    _para(
        """This server lets an AI assistant run commands on this machine, from
        anywhere. That is a lot of power to hand out, so most of what follows is
        about making sure it is really you connecting and nobody else.

        There are seven short questions. Each one explains itself. Where there is
        a sensible answer already it is shown in brackets, and pressing Enter
        accepts it.

        Nothing here is permanent. Everything gets written to a file called .env
        that you can edit, and you can run all of this again later with
        --setup."""
    )

    _heading(1, total, "The address people reach this server at")
    _para(
        """The assistant connects over the internet, so this machine needs an
        address on it. Usually that means a domain name pointed here, or a
        tunnel service that gives you one.

        Whatever you type has to be the address that actually reaches this
        machine from outside. If you have not set that up yet, stop here and do
        that first, because nothing else will work without it.

        It has to start with https, not http, because the sign-in step refuses
        to run over an unencrypted connection.

        Example: https://shell.mydomain.com"""
    )
    base_url = ""
    while not base_url:
        base_url = _ask("Web address of this server", required=True)
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            _para("That is not a full web address. It needs to look like "
                  "https://shell.mydomain.com, including the https:// part.")
            base_url = ""
        elif parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
            _para("That address uses http, which sends everything unencrypted. "
                  "Passkeys will not work over it and neither will sign-in. "
                  "Use https instead.")
            base_url = ""

    _heading(2, total, "Which apps may ask you to sign in")
    _para(
        """When an app wants access, it sends you here to sign in, and afterwards
        this server sends a one-time ticket back to that app.

        The danger is that anyone can build an app and point it at your server.
        They send you a link, you see this genuine sign-in page on your own
        genuine address, you sign in as normal, and the ticket goes to them
        instead of you. Nothing about the page would look wrong.

        The fix is this list. Only apps whose return address starts with
        something on it are allowed to ask at all. Everything else is turned
        away before you ever see a page.

        The suggested answer covers Claude, which is what most people want. Add
        others separated by commas if you know you need them."""
    )
    prefixes = _ask("Allowed return addresses", CLAUDE_CALLBACKS, required=True)

    _heading(3, total, "A name for your key")
    _para(
        """Your key needs a label so the server can refer to it. It is a name
        tag, nothing more. Any word works, and it is not a password, not
        secret, and nobody else ever sees it.

        The only rule is that the same word has to appear in two places. Setup
        writes both of them for you, so you do not have to think about it, but
        if you ever edit those files by hand and the words stop matching, sign-in
        stops working and the error will not tell you why."""
    )
    principal = _ask("Name for your key", "mcp-user")

    _heading(4, total, "Which network this listens on")
    _para(
        """Two options that matter.

        127.0.0.1 means only programs on this same machine can connect
        directly. Traffic from the internet arrives through your tunnel or
        proxy, which then hands it over locally. This is the safe answer and
        almost certainly what you want.

        0.0.0.0 means anything that can reach this machine on the network can
        connect straight to it, skipping whatever protection your tunnel or
        proxy provides. Only choose it if you know why you are doing so."""
    )
    host = _ask("Listen on", "127.0.0.1")

    _heading(5, total, "Which port")
    _para(
        """A port is just a numbered slot on this machine, so that several
        programs can share one address without colliding. The number itself does
        not matter as long as nothing else is already using it.

        If you have no reason to prefer another, keep the suggestion."""
    )
    port = _ask("Port number", "8811")

    _heading(6, total, "Which account commands run as")
    _para(
        """By default, commands run as the same account that runs this server.
        That account owns the server's own files: the list of who may sign in,
        the record of who is signed in, and the program itself.

        So a command could quietly rewrite the very things meant to keep it
        under control, and could leave itself a way back in that survives you
        revoking access.

        You can avoid that by naming a second, weaker account here. Commands run
        as that account instead, and it has no power over the server's files.

        This needs work outside setup: the account has to exist, and this server
        needs permission to switch to it without a password. Leave it blank for
        now if you have not done that. It is the honest default and you can turn
        it on later."""
    )
    exec_user = _ask("Account to run commands as, or blank")

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

    _setup_allowed_signers(principal)
    _setup_audit_key()

    print()
    _rule("=")
    print("  Done")
    _rule("=")
    print()
    _para(
        f"""Your answers are saved in {ENV_PATH}, readable only by you. Edit that
        file to change anything, or run this again with --setup.

        Starting the server now. To have it start on its own at boot, see
        mcp-shell.service.example."""
    )
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
