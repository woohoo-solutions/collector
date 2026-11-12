"""The ssh client for the devices OpenSSH will not talk to.

OpenSSH refuses an RSA host key under 1024 bits before it reads a single
option: the floor is compiled in (`SSH_RSA_MINIMUM_MODULUS_SIZE`), and
`RequiredRSASize` only raises it. Classic IOS generated 512-bit keys by
default for years, the device itself never complains, and an estate of old
access switches can hold dozens of them. Those devices are the customer's,
reachable with the customer's credentials, and DiscoNet does not get to leave
them out because one ssh client has an opinion about their key.

This module is the way in for them. It is a terminal relay built on asyncssh,
spawned by unicon in place of `ssh` through the connection's `command:`
(see :func:`relay_command`), so the login dialog is unicon's as it always is:

* the password is typed at this relay's own `Password:` prompt, the way
  OpenSSH asks for it, and never travels on a command line or in the
  environment;
* the host key is held to the estate's `known_hosts` exactly as
  `StrictHostKeyChecking=yes` holds OpenSSH to it — an unpinned key or a
  changed one ends the attempt before any credential is sent, with OpenSSH's
  own words, so the collector's diagnosis reads it unchanged;
* every legacy algorithm an old image may insist on (SHA-1 key exchange,
  CBC ciphers, `ssh-rsa` signatures) is offered after the modern ones, so a
  device that speaks anything better gets it.

It is only ever used after OpenSSH refused a device's host key for its
length; a device OpenSSH can talk to never reaches it. :func:`scan` is the
same client reading a host key without logging in, for the first-use pin that
`ssh-keyscan` cannot read either.

By hand: `disconet-ssh -l USER [-p PORT] --known-hosts FILE HOST`.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import os
import shlex
import sys
import warnings
from pathlib import Path
from typing import Any, Sequence

from netstate import hostkeys

SSH_PORT = hostkeys.SSH_PORT
# How a run names this client: in the manifest, the run summary and the log.
# Also the console command that runs it by hand (pyproject.toml).
CLIENT_NAME = "disconet-ssh"
RELAY_ENTRY = "import sys; from netstate.legacyssh import main; sys.exit(main())"
CONNECT_TIMEOUT = 30
# The terminal the device is asked for when the relay's own stdin is not one.
DEFAULT_COLUMNS = 200
DEFAULT_ROWS = 24
MAX_PASSWORD_PROMPTS = 3

# Offered after asyncssh's defaults, in this order: what classic IOS, early
# NX-OS and ASA images, and old Junos speak. GSS key exchange is left out:
# nothing here has a Kerberos ticket to offer.
LEGACY_KEX = (
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
)
LEGACY_CIPHERS = ("aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc")
LEGACY_MACS = ("hmac-sha1-96", "hmac-md5", "hmac-md5-96")
LEGACY_HOST_KEY_ALGS = ("ssh-rsa", "ssh-dss")

# OpenSSH's words for the same refusals, so connect_failure_hint and the
# wizard's check read a refusal from here as they read one from `ssh`.
PERMISSION_RETRY = "Permission denied, please try again."
EXIT_REFUSED = 255


def _quiet() -> None:
    """Keep cryptography's deprecation of finite-field DH off the terminal.

    It is printed on stderr, which is the session unicon reads: a warning
    line in the middle of a login dialog is noise to the reader and a
    pattern risk to the state machine. The fact itself is in this module's
    documentation and in OPERATING.md.
    """
    warnings.filterwarnings("ignore", message=".*Diffie-Hellman over finite fields.*")
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="asyncssh")


def available() -> bool:
    """Is asyncssh importable here? Without it there is no relay to fall back to."""
    try:
        import asyncssh  # noqa: F401
    except ImportError:
        return False
    return True


def relay_command(
    address: str, port: int | str | None, username: str, known_hosts: Path | str
) -> str:
    """The command unicon spawns in place of `ssh` for one device.

    This interpreter, not a script on PATH: the relay runs under the Python
    that runs the collection, installed or from a checkout alike. `-c`, not
    `-m`: importing the netstate package imports this module, and `-m` on an
    already imported module prints runpy's RuntimeWarning onto the terminal
    unicon is reading the login from.
    """
    return shlex.join([
        sys.executable, "-c", RELAY_ENTRY,
        "-l", username,
        "-p", str(int(port or SSH_PORT)),
        "--known-hosts", str(Path(known_hosts).resolve()),
        address,
    ])


def _algorithms(defaults: Sequence[bytes], legacy: Sequence[str]) -> list[str]:
    names = [name.decode() for name in defaults]
    return names + [name for name in legacy if name not in names]


def connect_options() -> dict[str, Any]:
    """asyncssh's defaults first, then the legacy algorithms an old image needs."""
    from asyncssh.encryption import get_default_encryption_algs
    from asyncssh.kex import get_default_kex_algs
    from asyncssh.mac import get_default_mac_algs
    from asyncssh.public_key import get_default_public_key_algs

    return {
        "kex_algs": _algorithms(get_default_kex_algs(), LEGACY_KEX),
        "encryption_algs": _algorithms(get_default_encryption_algs(), LEGACY_CIPHERS),
        "mac_algs": _algorithms(get_default_mac_algs(), LEGACY_MACS),
        "server_host_key_algs": _algorithms(get_default_public_key_algs(), LEGACY_HOST_KEY_ALGS),
        # No agent, no key files, no ~/.ssh/config: the login is the password
        # unicon types, as it is for every other device in the testbed.
        "agent_path": None,
        "client_keys": None,
        "config": None,
        "preferred_auth": ["keyboard-interactive", "password"],
    }


def _key_fields(key: Any) -> tuple[str, str]:
    """(type, base64 blob) as known_hosts writes them."""
    return key.get_algorithm(), base64.b64encode(key.public_data).decode()


# --------------------------------------------------------------------------
# Reading a host key without logging in
# --------------------------------------------------------------------------


def scan(address: str, port: int = SSH_PORT, timeout: int = hostkeys.SCAN_TIMEOUT) -> list[hostkeys.ScannedKey]:
    """The host key the device offers, read the way the relay will read it.

    Empty where asyncssh is missing or nothing answered; never raises.
    """
    if not available():
        return []
    _quiet()
    try:
        return asyncio.run(_scan(address, int(port), timeout))
    except Exception:  # noqa: BLE001 - nothing read is the answer
        return []


async def _scan(address: str, port: int, timeout: int) -> list[hostkeys.ScannedKey]:
    import asyncssh

    # The ciphers and MACs go in through an options object: get_server_host_key
    # takes only the key exchange and host key lists as keywords, and a device
    # that speaks nothing but CBC would end the scan at the cipher negotiation.
    # Its own two keywords are passed as well: left out, they default to
    # asyncssh's lists and override the ones in the options object.
    chosen = connect_options()
    options = asyncssh.SSHClientConnectionOptions(**chosen)
    key = await asyncio.wait_for(
        asyncssh.get_server_host_key(
            address, port, options=options, config=None,
            kex_algs=chosen["kex_algs"], server_host_key_algs=chosen["server_host_key_algs"],
        ),
        timeout,
    )
    if key is None:
        return []
    key_type, blob = _key_fields(key)
    return [hostkeys.ScannedKey(hostkeys.host_pattern(address, port), key_type, blob)]


# --------------------------------------------------------------------------
# The relay
# --------------------------------------------------------------------------


class Refused(Exception):
    """Ended before a session: the message is printed as OpenSSH would print it."""


class _Terminal:
    """This process's stdin: raw while the relay runs, restored on every exit."""

    def __init__(self, fd: int):
        self.fd = fd
        self.saved: Any = None

    def __enter__(self) -> "_Terminal":
        if os.isatty(self.fd):
            import termios
            import tty

            self.saved = termios.tcgetattr(self.fd)
            tty.setraw(self.fd)
        return self

    def __exit__(self, *_exc: Any) -> None:
        if self.saved is not None:
            import termios

            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.saved)

    def size(self) -> tuple[int, int]:
        try:
            columns, rows = os.get_terminal_size(self.fd)
        except OSError:
            return DEFAULT_COLUMNS, DEFAULT_ROWS
        return columns or DEFAULT_COLUMNS, rows or DEFAULT_ROWS


def _write(text: str) -> None:
    # \r\n: the terminal is raw, and a bare \n would not return the carriage.
    os.write(sys.stdout.fileno(), text.replace("\r\n", "\n").replace("\n", "\r\n").encode())


def _read_line(prompt: str, echo: bool) -> str:
    """One answer typed at this relay's own prompt: unicon's, as it answers `ssh`'s.

    The terminal is raw, so nothing is echoed unless asked for, and a
    password never is.
    """
    _write(prompt)
    typed = bytearray()
    while True:
        chunk = os.read(sys.stdin.fileno(), 1)
        if not chunk:
            raise Refused("")
        if chunk in (b"\r", b"\n"):
            _write("\n")
            return typed.decode(errors="replace")
        if chunk == b"\x03":
            raise KeyboardInterrupt
        if chunk in (b"\x7f", b"\x08"):
            del typed[-1:]
            continue
        typed += chunk
        if echo:
            os.write(sys.stdout.fileno(), chunk)


def _host_key_refusal(known_hosts: Path, address: str, port: int, key: Any) -> str | None:
    """OpenSSH's words for a key that is not the pinned one, or None to go on."""
    pattern = hostkeys.host_pattern(address, port)
    pinned = hostkeys.known_keys(known_hosts, address, port)
    key_type, blob = _key_fields(key)
    if (key_type, blob) in pinned:
        return None
    name = {"ssh-rsa": "RSA", "ssh-dss": "DSA", "ssh-ed25519": "ED25519"}.get(key_type, "ECDSA")
    fingerprint = hostkeys.fingerprint(blob)
    if not pinned:
        return (
            f"No {name} host key is known for {pattern} and you have requested strict checking.\n"
            "Host key verification failed.\n"
        )
    return (
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
        "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
        "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n"
        f"The fingerprint for the {name} key sent by the remote host is\n{fingerprint}.\n"
        f"Offending key for {pattern} in {known_hosts}\n"
        "Host key verification failed.\n"
    )


def _client_class(known_hosts: Path, address: str, port: int) -> type:
    import asyncssh

    class Client(asyncssh.SSHClient):
        """Holds the session to the pins and asks for the password at this terminal."""

        def __init__(self) -> None:
            self.refusal: str | None = None
            self.prompts = 0

        def validate_host_public_key(self, host: str, addr: str, port_: int, key: Any) -> bool:
            self.refusal = _host_key_refusal(known_hosts, address, port, key)
            return self.refusal is None

        def password_auth_requested(self) -> str | None:
            if self.prompts >= MAX_PASSWORD_PROMPTS:
                return None
            if self.prompts:
                _write(PERMISSION_RETRY + "\n")
            self.prompts += 1
            return _read_line("Password: ", echo=False)

        def kbdint_auth_requested(self) -> str | None:
            return ""

        def kbdint_challenge_received(
            self, name: str, instructions: str, lang: str, prompts: Sequence[tuple[str, bool]]
        ) -> list[str] | None:
            if not prompts:
                return []
            if self.prompts >= MAX_PASSWORD_PROMPTS:
                return None
            if self.prompts:
                _write(PERMISSION_RETRY + "\n")
            self.prompts += 1
            if instructions:
                _write(instructions.rstrip("\n") + "\n")
            return [_read_line(prompt or "Password: ", echo) for prompt, echo in prompts]

    return Client


async def _relay(username: str, address: str, port: int, known_hosts: Path, timeout: int) -> int:
    import asyncssh

    client_class = _client_class(known_hosts, address, port)
    holder: dict[str, Any] = {}

    def factory() -> Any:
        holder["client"] = client_class()
        return holder["client"]

    stdin, stdout = sys.stdin.fileno(), sys.stdout.fileno()
    with _Terminal(stdin) as terminal:
        try:
            connection = await asyncssh.connect(
                address, port, username=username, known_hosts=([], [], []),
                client_factory=factory, connect_timeout=timeout, **connect_options(),
            )
        except asyncssh.HostKeyNotVerifiable:
            raise Refused(holder["client"].refusal or "Host key verification failed.\n") from None
        except asyncssh.PermissionDenied:
            raise Refused(f"{username}@{address}: Permission denied (password).\n") from None
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError) as exc:
            reason = "Connection timed out" if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) else (
                "Connection refused" if isinstance(exc, ConnectionRefusedError) else (exc.strerror or str(exc))
            )
            raise Refused(f"ssh: connect to host {address} port {port}: {reason}\n") from None
        except asyncssh.Error as exc:
            raise Refused(f"ssh: {address} port {port}: {exc.reason}\n") from None

        async with connection:
            columns, rows = terminal.size()
            process = await connection.create_process(
                term_type=os.environ.get("TERM") or "vt100",
                term_size=(columns, rows), encoding=None,
            )
            loop = asyncio.get_running_loop()

            def forward() -> None:
                try:
                    data = os.read(stdin, 4096)
                except OSError:
                    data = b""
                if data:
                    process.stdin.write(data)
                else:
                    loop.remove_reader(stdin)
                    process.stdin.write_eof()

            loop.add_reader(stdin, forward)
            try:
                while True:
                    data = await process.stdout.read(4096)
                    if not data:
                        break
                    os.write(stdout, data)
            finally:
                loop.remove_reader(stdin)
            await process.wait_closed()
            status = process.exit_status
        _write(f"Connection to {address} closed.\n")
    return status if isinstance(status, int) and status >= 0 else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="disconet-ssh",
        description="ssh to a device whose RSA host key OpenSSH refuses for its length",
    )
    parser.add_argument("-l", dest="username", required=True)
    parser.add_argument("-p", dest="port", type=int, default=SSH_PORT)
    parser.add_argument("--known-hosts", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=CONNECT_TIMEOUT)
    parser.add_argument("address")
    args = parser.parse_args(argv)
    if not available():
        sys.stderr.write("disconet-ssh: asyncssh is not installed (pip install asyncssh)\n")
        return EXIT_REFUSED
    _quiet()
    try:
        return asyncio.run(_relay(args.username, args.address, args.port, args.known_hosts, args.timeout))
    except Refused as refused:
        message = str(refused)
        if message:
            with contextlib.suppress(OSError):
                _write(message)
        return EXIT_REFUSED
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
