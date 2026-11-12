"""Host keys: the policy every login from this machine runs under.

Strict by default. Every ssh session DiscoNet spawns on this machine is told
to trust only the keys pinned in one OpenSSH `known_hosts` file beside the
testbed, and to refuse anything else without asking:

    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<file> -o GlobalKnownHostsFile=/dev/null

So OpenSSH itself enforces the pin, and the file is one `ssh-keygen -F`,
`ssh-keygen -R` and `ssh-keyscan` already know how to read and write. Neither
the user's `~/.ssh/known_hosts` nor the system one counts: what a collection
trusts is what this estate pinned, nothing it inherited.

A key is pinned in one of two ways only: an engineer at a terminal is shown
its fingerprint and says yes (the first-use prompt), or it is added to the
file by hand after being checked out of band. Nothing here ever accepts a key
by itself, and unicon is told to answer "no" to the ssh client's own
"continue connecting?" question (see `collector.login_dialog`), which is the
only question it would otherwise answer "yes" to.

Through a jump host the ssh client that checks the device's key is the jump
host's, with the jump host's own `known_hosts`. These options would be typed
on the jump host, naming a file that is not there, so a hop is left to that
client; the jump host itself is spawned here and is held to this file.

Reading a key (`ssh-keyscan`) is an unauthenticated SSH handshake: no
credential is sent and no command runs. It is the same contact the login
itself starts with.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

log = logging.getLogger(__name__)

KNOWN_HOSTS_NAME = "known_hosts"
SSH_PORT = 22
SCAN_TIMEOUT = 5

# The options that make the pin binding. First on the command line, because
# OpenSSH keeps the first value it is given for an option: a testbed's own
# `-o StrictHostKeyChecking=no` after these changes nothing.
POLICY_KEYS = ("StrictHostKeyChecking", "UserKnownHostsFile", "GlobalKnownHostsFile")

# The key types an ssh-keyscan line may carry. Anything else is not a key.
KEY_TYPES = frozenset({
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
})


def known_hosts_path(testbed_path: Path | str) -> Path:
    """Where an estate's pins live: beside its testbed.

    `estates/<name>/known_hosts` for an estate, `./known_hosts` for a
    testbed in the working directory.
    """
    return Path(testbed_path).resolve().parent / KNOWN_HOSTS_NAME


def policy_options(path: Path | str) -> str:
    """The ssh options that hold a session to the pins in ``path``."""
    return (
        "-o StrictHostKeyChecking=yes "
        f"-o UserKnownHostsFile={shlex.quote(str(Path(path).resolve()))} "
        "-o GlobalKnownHostsFile=/dev/null"
    )


def without_policy(options: str | None, path: Path | str | None) -> str | None:
    """``options`` with the policy prefix taken off, for what a run records.

    What finalize writes into a testbed is what the device needed, not the
    absolute path of this machine's pin file.
    """
    if not options or path is None:
        return options
    prefix = policy_options(path)
    if options == prefix:
        return None
    if options.startswith(prefix + " "):
        return options[len(prefix) + 1:] or None
    return options


def host_pattern(address: str, port: int = SSH_PORT) -> str:
    """How known_hosts names a host: `10.0.0.1`, or `[10.0.0.1]:2222` off port 22."""
    return address if int(port) == SSH_PORT else f"[{address}]:{int(port)}"


def _hashed_match(entry: str, pattern: str) -> bool:
    """Does a hashed host field (`|1|salt|hash`) name ``pattern``?"""
    parts = entry.split("|")
    if len(parts) != 4 or parts[1] != "1":
        return False
    try:
        salt = base64.b64decode(parts[2])
        expected = base64.b64decode(parts[3])
    except (ValueError, TypeError):
        return False
    digest = hmac.new(salt, pattern.encode(), hashlib.sha1).digest()
    return hmac.compare_digest(digest, expected)


def known_keys(path: Path | str, address: str, port: int = SSH_PORT) -> list[tuple[str, str]]:
    """The (type, base64 key) pairs pinned for this address and port.

    Plain and hashed entries are read; a `@revoked` or `@cert-authority`
    line, a negated or wildcard pattern, is not a pin and is passed over.
    """
    pattern = host_pattern(address, port)
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("@"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        hosts, key_type, key = fields[0], fields[1], fields[2]
        names = hosts.split(",")
        if any(_hashed_match(name, pattern) if name.startswith("|") else name == pattern for name in names):
            found.append((key_type, key))
    return found


def is_pinned(path: Path | str, address: str, port: int = SSH_PORT) -> bool:
    return bool(known_keys(path, address, port))


def rsa_bits(key_type: str, key: str) -> int | None:
    """The modulus size of an `ssh-rsa` key blob, or None for any other key.

    Read from the wire format itself (string type, mpint e, mpint n), so it
    needs no crypto library and works on a key no client would load.
    """
    if key_type != "ssh-rsa":
        return None
    try:
        blob = base64.b64decode(key)
        fields = []
        offset = 0
        for _ in range(3):
            length = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            fields.append(blob[offset:offset + length])
            offset += length
        modulus = int.from_bytes(fields[2], "big")
    except (ValueError, TypeError, IndexError):
        return None
    return modulus.bit_length() or None


def fingerprint(key: str) -> str:
    """OpenSSH's SHA256 fingerprint of a base64 key blob, as `ssh-keygen -l` prints it."""
    blob = base64.b64decode(key)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


@dataclass(frozen=True)
class ScannedKey:
    """One key a device offered, as a line ready for known_hosts."""

    pattern: str
    key_type: str
    key: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.key)

    @property
    def line(self) -> str:
        return f"{self.pattern} {self.key_type} {self.key}"


# Asked for one at a time, in this order, when the first scan read nothing.
# ssh-keyscan opens one connection per key type it asks for, all at once, and
# an IOS-XR 7.x server (OpenSSH_8.0 PKIX on an NCS 540) closes most of a
# burst like that from one source: the ED25519 probe was among those closed,
# and the one that got through asked for a type the box does not hold. One
# connection asking for one type is answered. Seen on 6 November 2026, on 20
# of 65 NCS 540s in one estate.
SEQUENTIAL_KEY_TYPES = ("ed25519", "rsa", "ecdsa")


def _run_keyscan(address: str, port: int, timeout: int, key_type: str | None = None) -> str:
    command = ["ssh-keyscan", "-T", str(timeout), "-p", str(int(port))]
    if key_type:
        command += ["-t", key_type]
    listed = subprocess.run(
        [*command, address],
        capture_output=True, text=True, timeout=timeout * 4 + 5, check=False,
    )
    # stderr too: the `# host:port SSH-2.0-...` banner line is printed there,
    # and it is what says a server answered at all. No line of it parses as a key.
    return (listed.stdout or "") + (listed.stderr or "")


def scan(
    address: str,
    port: int = SSH_PORT,
    timeout: int = SCAN_TIMEOUT,
    runner: Callable[..., str] | None = None,
    fallback: Callable[[str, int, int], list[ScannedKey]] | None = None,
) -> list[ScannedKey]:
    """The host keys the device offers, read without logging in.

    Every line is checked before it is kept: it must name this address, a
    known key type and a key that decodes. Whatever else the tool printed is
    not a pin candidate.

    One scan asking for every type comes first. When it reads nothing, each
    of SEQUENTIAL_KEY_TYPES is asked for on its own connection, one after the
    other, until one answers (see SEQUENTIAL_KEY_TYPES for why), but only
    when the first scan shows a server answered with its SSH banner. One key
    is enough: the ssh client prefers the type a host has pinned.

    Last, where a server answered and ssh-keyscan still read nothing, the key
    is read by DiscoNet's own client (``fallback``; netstate.legacyssh.scan
    unless a ``runner`` is given): ssh-keyscan is OpenSSH, and refuses an RSA
    host key under 1024 bits exactly as the ssh client does. The key it reads
    is confirmed and pinned like any other, and the collection's own client
    is held to it.
    """
    pattern = host_pattern(address, port)
    if fallback is None and runner is None:
        from netstate import legacyssh

        fallback = legacyssh.scan
    run = runner or _run_keyscan
    first = _scan_output(run, address, port, timeout, None)
    keys = _parsed(pattern, first)
    if keys:
        return keys
    if "SSH-" not in first:
        # No server spoke: the address is down or not SSH. Asking again, one
        # type at a time, would cost a timeout per type and read nothing.
        return []
    for key_type in SEQUENTIAL_KEY_TYPES:
        keys = _parsed(pattern, _scan_output(run, address, port, timeout, key_type))
        if keys:
            log.info(
                "%s: host key read asking for %s alone; a scan asking for every type "
                "at once read nothing", pattern, key_type,
            )
            return keys
    if fallback is not None:
        keys = [key for key in fallback(address, int(port), timeout) if key.pattern == pattern]
        if keys:
            bits = rsa_bits(keys[0].key_type, keys[0].key)
            log.warning(
                "%s: host key read by DiscoNet's own ssh client; ssh-keyscan read none%s",
                pattern,
                f" (an RSA key of {bits} bits, under OpenSSH's floor of 1024)"
                if bits and bits < 1024 else "",
            )
            return keys
    return []


def _scan_output(
    run: Callable[..., str], address: str, port: int, timeout: int, key_type: str | None
) -> str:
    try:
        if key_type is None:
            return run(address, port, timeout) or ""
        return run(address, port, timeout, key_type) or ""
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("could not read the host key of %s: %s", host_pattern(address, port), exc)
        return ""


def _parsed(pattern: str, output: str) -> list[ScannedKey]:
    keys: list[ScannedKey] = []
    for line in output.splitlines():
        fields = line.strip().split()
        if len(fields) != 3 or line.startswith("#"):
            continue
        host, key_type, key = fields
        if host != pattern or key_type not in KEY_TYPES:
            continue
        try:
            base64.b64decode(key, validate=True)
        except (ValueError, TypeError):
            continue
        keys.append(ScannedKey(pattern, key_type, key))
    return keys


def _open_private(path: Path) -> int:
    """Open for append, created 600; an existing file is narrowed to 600 too."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    except OSError:  # pragma: no cover - a filesystem without modes
        pass
    return descriptor


def pin(
    path: Path | str, device: str, keys: Sequence[ScannedKey], one_by_one: bool = True
) -> None:
    """Append ``keys`` to the pin file, with a comment naming who and when.

    ``one_by_one`` False records a key pinned under "yes to all": shown at
    the terminal, not confirmed by itself, and the file says so.
    """
    if not keys:
        return
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    how = (
        "after the fingerprint was confirmed" if one_by_one
        else "under 'yes to all': the fingerprint was shown, not confirmed by itself"
    )
    text = f"# {device}: pinned by DiscoNet {stamp} {how}\n"
    text += "".join(f"{key.line}\n" for key in keys)
    descriptor = _open_private(Path(path))
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(text)


# --------------------------------------------------------------------------
# Applying the policy to a testbed's connections
# --------------------------------------------------------------------------


def _connections(device: Any) -> list[Any]:
    connections = getattr(device, "connections", None) or {}
    try:
        values = list(connections.values())
    except AttributeError:
        return []
    return [connection for connection in values if hasattr(connection, "get")]


def spawned_here(connection: Any) -> bool:
    """Is this an ssh session this machine's own client opens?

    Not a telnet connection, and not a hop typed on a jump host.
    """
    if not hasattr(connection, "get") or not connection.get("ip"):
        return False
    if str(connection.get("protocol") or "ssh").lower() != "ssh":
        return False
    return not connection.get("proxy")


def apply(device: Any, path: Path | str) -> list[str]:
    """Put the policy in front of every ssh connection this machine spawns for ``device``.

    Idempotent. Returns the policy keys the testbed set itself on those
    connections, which the policy now overrides, so the caller can say so.
    """
    prefix = policy_options(path)
    overridden: list[str] = []
    for connection in _connections(device):
        if not spawned_here(connection):
            continue
        current = str(connection.get("ssh_options") or "")
        if current == prefix or current.startswith(prefix + " "):
            continue
        overridden.extend(key for key in POLICY_KEYS if key.lower() in current.lower())
        connection["ssh_options"] = f"{prefix} {current}".strip()
    return overridden


@dataclass(frozen=True)
class Target:
    """One address this machine will open an ssh session to."""

    device: str
    address: str
    port: int

    @property
    def pattern(self) -> str:
        return host_pattern(self.address, self.port)


def targets(devices: Iterable[Any]) -> list[Target]:
    """Every (device, address, port) the run's own ssh client will open, once each."""
    found: dict[tuple[str, int], Target] = {}
    for device in devices:
        for connection in _connections(device):
            if not spawned_here(connection):
                continue
            try:
                port = int(connection.get("port") or SSH_PORT)
            except (TypeError, ValueError):
                port = SSH_PORT
            address = str(connection.get("ip"))
            found.setdefault((address, port), Target(str(getattr(device, "name", "")), address, port))
    return list(found.values())


# What the first-use prompt is asked: the device, its address and port, and
# the keys it offered. True pins them.
# What a first-use prompt answers: True to pin this key, False not to, or
# TRUSTED_ALL for a key pinned under an earlier "yes to all" in this run.
TRUSTED_ALL = "all"
Confirm = Callable[[Target, Sequence[ScannedKey]], "bool | str"]


def confirm_first_use(
    devices: Iterable[Any],
    path: Path | str,
    confirm: Confirm,
    scanner: Callable[[str, int], list[ScannedKey]] | None = None,
) -> dict[str, str]:
    """Ask about every unpinned key, one target at a time, before any login.

    Returns, by address pattern, what happened: "pinned", "declined" or
    "unreadable". A target already pinned is not contacted.
    """
    outcome: dict[str, str] = {}
    for target in targets(devices):
        if is_pinned(path, target.address, target.port):
            continue
        keys = (scanner or scan)(target.address, target.port)
        if not keys:
            outcome[target.pattern] = "unreadable"
            log.warning(
                "%s: could not read a host key from %s (ssh-keyscan read none, asking "
                "for every type at once or for %s one at a time, and neither did "
                "DiscoNet's own ssh client), so there is nothing to confirm; the login "
                "will be refused as unpinned",
                target.device, target.pattern, ", ".join(SEQUENTIAL_KEY_TYPES),
            )
            continue
        answer = confirm(target, keys)
        if answer:
            one_by_one = answer != TRUSTED_ALL
            pin(path, target.device, keys, one_by_one=one_by_one)
            outcome[target.pattern] = "pinned"
            log.info(
                "%s: host key of %s pinned in %s%s", target.device, target.pattern, path,
                "" if one_by_one else " (yes to all)",
            )
        else:
            outcome[target.pattern] = "declined"
            log.warning("%s: host key of %s not trusted; it will not be logged into", target.device, target.pattern)
    return outcome


def unpinned_advice(path: Path | str, address: str = "<address>", port: int = SSH_PORT) -> str:
    """How to pin a key without the prompt, for a run nobody is watching."""
    port_flag = f"-p {port} " if int(port) != SSH_PORT else ""
    return (
        f"its host key is not pinned in {path}, and DiscoNet never accepts a key by itself. "
        f"Run collect once at a terminal to be shown the fingerprint and asked, or read it "
        f"with 'ssh-keyscan {port_flag}{address}', check the fingerprint "
        f"('ssh-keygen -lf -') against the device's own 'show crypto key mypubkey' or "
        f"equivalent, and append the line to that file. ssh-keyscan reads nothing from an "
        f"RSA key under 1024 bits; the terminal run reads that one with DiscoNet's own client"
    )
