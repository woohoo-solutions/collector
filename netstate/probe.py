"""One TCP probe of one address: the sweep's, and the telnet fallback's.

Connects, reads at most one short banner, and closes. It sends nothing, so it
needs no allowlist entry; it is the only thing the engine does to an address
before a login.
"""

from __future__ import annotations

import socket


SSH_PORT = 22


# Asked only of the addresses that were silent on 22. An estate old enough to
# have devices reachable by telnet alone still has to be documented whole, and
# a device left out of the testbed is a device left out of the document.
TELNET_PORT = 23
TELNET = "telnet"


# How long one TCP connect gets. A management network is close and a router's
# SSH listener answers immediately or not at all; the cost of being generous
# here is paid once per dead address, and a /22 has a lot of dead addresses.
DEFAULT_SWEEP_TIMEOUT = 1.5


def probe_address(
    address: str, port: int = SSH_PORT, timeout: float = DEFAULT_SWEEP_TIMEOUT
) -> tuple[bool, str]:
    """Is there an SSH listener here? Returns (answered, banner).

    The banner is read because it costs one short receive on a socket that is
    already open, and because it is the only thing an unauthenticated probe can
    learn about what the device is. It is a hint, never a fact: see
    `os_hint` in the inventory reader.
    """
    try:
        with socket.create_connection((address, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            try:
                banner = connection.recv(128).decode("utf-8", "replace").strip()
            except (socket.timeout, OSError):
                banner = ""
            return True, banner.splitlines()[0] if banner else ""
    except (socket.timeout, OSError):
        return False, ""
