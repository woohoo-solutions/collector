"""Reading a few facts out of a collected device's own output.

The engine needs these while it collects, not only when a document is built:
the hostname a device gives decides what it is called from the moment it
answers; its version and serials make one box reached under two names one row
of the estate; and the Junos LLDP brief table read as text is how the crawl
follows a neighbour Genie could not parse (BUG-207). They read the snapshot
through the platform registry and depend on nothing above the engine; the
topology and the testbed writer import them from here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable

from netstate.inheritance import effective_lines
from netstate.ledger import ConfigPath, consume
from netstate.naming import hostname_key, is_interface_name, normalise_hostname
from netstate.platforms import VersionFacts, platform_for

if TYPE_CHECKING:
    from netstate.collector import Snapshot


# Where a hostname can be read from, in order of how much it is worth. The
# running configuration is first because both platforms state it the same way
# and neither abbreviates it; the parsed `show version` is a fallback for a
# device whose configuration was not collected. Junos is the other way round,
# for the reason `_hostname_from` gives.
# `hostname X` on the Cisco platforms; `host-name X;` inside `system { }` on
# Junos, where the line is indented and ends in a semicolon.
# `switchname X` is the older Nexus spelling of the same line.
HOSTNAME_IN_CONFIG = re.compile(
    r"^\s*(?:host(?:name|-name)|switchname)\s+(?P<name>[^\s;]+)\s*;?\s*$", re.MULTILINE
)


VERSION_COMMAND = "show version"


def _hostname_from(snapshot: Any, device: str, declared_os: str) -> str:
    """The name the device calls itself, from its own output.

    Not from the testbed, and not from a neighbour's CDP entry: this is the one
    fact that decides what the device is called in every document afterwards,
    so it comes from the device's own mouth or it does not come at all.
    """
    config = snapshot.config(device)
    platform = platform_for(declared_os)
    if platform is not None and platform.config_nested:
        # A Junos configuration can state several names: a dual-RE box names
        # each routing engine under `groups`, which is printed before
        # `system`, and its own `system host-name` overrides them. `show
        # version` says the one the box runs under; without it `system
        # host-name` is read from the configuration the box runs, its groups
        # applied (`junos_paths`): its own, or an engine group's where only
        # one engine group is applied. A box that applies `re0` and `re1`
        # and names itself only there does not say which engine answered,
        # and the resolver applies neither (BUG-291).
        named = platform.version(snapshot.state(device, VERSION_COMMAND)).hostname
        if named:
            return named
        for path in junos_paths(config):
            if len(path) == 2 and path[0] == "system" and path[1].startswith("host-name "):
                consume(device, [path], "readers.hostname")
                return path[1].split()[1]
        return ""
    match = HOSTNAME_IN_CONFIG.search(config)
    if match:
        consume(device, [config.count("\n", 0, match.start("name")) + 1], "readers.hostname")
        return match.group("name")
    if platform is None:
        return ""
    return platform.version(snapshot.state(device, VERSION_COMMAND)).hostname


_JUNOS_ANNOTATION = re.compile(r"\s*##.*$")


def junos_paths(config: str, inherit: bool = True) -> list[list[str]]:
    """Junos braces flattened into the path each statement sits on.

    `system { ntp { server 192.0.2.1 prefer; } }` becomes
    `["system", "ntp", "server 192.0.2.1 prefer"]`, which is the same shape
    the Cisco indentation gives, so one reader style serves both. A stanza
    header is a path of its own as well as a prefix, because `system services
    ssh { ... }` and `system services telnet;` say the same kind of thing.
    An `inactive:` stanza is configuration the device is not running, and is
    left out with everything under it; `protect:` only locks a statement
    against change and is dropped from its text. Each path is a `ConfigPath`,
    which also carries the line number of each element for the statement
    ledger.

    With `inherit` (the default) the paths are those of the configuration
    the device runs: the `groups` that `apply-groups` names are applied in
    place (`netstate.inheritance`), not where an `apply-groups-except`
    takes them away, an inherited statement carries the line number the
    group wrote it on, and neither `groups`, `apply-groups` nor
    `apply-groups-except` is a path. What the resolver could not resolve is
    in `netstate.inheritance.resolve(config, nested=True).unresolved`. `inherit=False` reads the text as written, for the
    stanza-level figure, which counts lines where they stand.
    """
    return [path for path, _leaf in _junos_walk(config, inherit)]


def junos_leaf_paths(config: str, inherit: bool = True) -> list[list[str]]:
    """`junos_paths`, statements only: no path that opens a block."""
    return [path for path, leaf in _junos_walk(config, inherit) if leaf]


def _junos_walk(config: str, inherit: bool) -> list[tuple[ConfigPath, bool]]:
    if inherit:
        lines = [(line.line_no, str(line)) for line in effective_lines(config, nested=True)]
    else:
        lines = list(enumerate(config.splitlines(), 1))
    paths: list[tuple[ConfigPath, bool]] = []
    stack: list[str] = []
    numbers: list[int] = []
    skip_from: int | None = None
    for number, raw in lines:
        line = _JUNOS_ANNOTATION.sub("", raw.strip())
        if not line or line.startswith(("#", "/*", "*")):
            continue
        if line == "}":
            if stack:
                stack.pop()
                numbers.pop()
            if skip_from is not None and len(stack) < skip_from:
                skip_from = None
            continue
        opens = line.endswith("{")
        text = line[:-1].strip() if opens else line.rstrip(";").strip()
        inactive = text.startswith("inactive:")
        text = _PROTECT.sub("", text)
        if opens:
            stack.append(text)
            numbers.append(number)
            if inactive and skip_from is None:
                skip_from = len(stack)
            if skip_from is None:
                paths.append((ConfigPath(stack, numbers), False))
            continue
        if skip_from is None and not inactive:
            paths.append((ConfigPath([*stack, text], [*numbers, number]), True))
    return paths


_PROTECT = re.compile(r"^protect:\s*")


@dataclass
class RawLink:
    """One neighbour relationship as a single device reported it."""

    local_device: str
    local_interface: str
    remote_device: str
    remote_interface: str
    protocol: str
    remote_platform: str | None = None
    remote_software: str | None = None
    # The far end's name whole, domain and all, where the reader shortened
    # it: what tells apart two testbed entries that share a short name.
    remote_reported: str = ""


def _far_port(port_id: Any, description: Any) -> str:
    """The far interface, from whichever LLDP field actually names one.

    Junos advertises the numeric ifIndex as its port ID by default and puts
    the interface name in the port description, so a Cisco neighbour of a
    Junos box reports `517` and `ge-0/0/1` in that order. The description is
    taken wherever the port ID is not shaped like an interface and the
    description is.
    """
    port = str(port_id or "").strip()
    text = str(description or "").strip()
    if port and is_interface_name(port):
        return port
    if text and is_interface_name(text):
        return text
    return port or text


# The Junos brief table: `Local Interface  Parent Interface  Chassis Id  Port
# info  System Name`. A row is read by its words, not cut where the header
# puts each column: a Port info wider than its column pushes the System Name
# to the right, and a cut at the header's offset makes a node of the two.
_LLDP_HEADER_COLUMNS = ("Local Interface", "Parent Interface", "Chassis Id", "Port info", "System Name")
_LLDP_CHASSIS_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)


def _junos_lldp_links_from_text(device: str, text: str, known: Iterable[str] = ()) -> list[RawLink]:
    """The brief table's rows; `known` is the hostname keys of the devices the snapshot holds.

    The device reading the table is no neighbour of its own, and a far
    port's description names it as often as anything: `uplink to PE3`.
    """
    known = set(known) - {hostname_key(device)}
    lines = text.splitlines()
    header = next((line for line in lines if all(c in line for c in _LLDP_HEADER_COLUMNS)), None)
    if header is None:
        return []
    system_column = header.index("System Name")
    links: list[RawLink] = []
    for line in lines[lines.index(header) + 1:]:
        words = line.split()
        if not words or not is_interface_name(words[0]):
            continue
        # The local port first, the System Name last: one word, and only
        # where it stands under its column or right of it. A neighbour that
        # sent none leaves the row ending in its Port info. The Chassis Id is
        # told by its MAC shape, after a Parent Interface or a `-`, and the
        # Port info is what lies between, spaces and all.
        chassis = next((i for i in (1, 2) if i < len(words) and _LLDP_CHASSIS_MAC.match(words[i])), 2)
        if len(words) < chassis + 2:
            continue
        local, info = words[0], words[chassis + 1 :]
        # The last word is the System Name only where the Port info cannot
        # have it: the Port info ends inside its own column, or is one
        # interface name that ran past it. A free-text Port info wider than
        # its column is a port description, and its last word is as likely a
        # word of it as a name; read as one, "Port 1 of some unnamed device"
        # was a device called `device`. Unless the snapshot holds another
        # device of that name: a description that ends in one names it,
        # whether or not the neighbour sent it as well. Its shape is never
        # the test.
        start = len(line.rstrip()) - len(words[-1])
        named = len(info) > 1 and start >= system_column and (
            len(line[:start].rstrip()) < system_column
            or (len(info) == 2 and is_interface_name(info[0]))
            or hostname_key(words[-1]) in known
        )
        reported = ""
        if named:
            port, remote, reported = " ".join(info[:-1]), normalise_hostname(words[-1]), words[-1]
        elif _LLDP_CHASSIS_MAC.match(words[chassis]):
            # Nameless, the neighbour is known by its chassis id, which the
            # topology lists as a gap and counts as no device.
            port, remote = " ".join(info), words[chassis]
        else:
            continue
        if not remote:
            continue
        links.append(
            RawLink(
                local_device=device, local_interface=local, remote_device=remote,
                remote_interface=_far_port(port, ""), protocol="lldp", remote_reported=reported,
            )
        )
    return links


def device_version(snapshot: Snapshot, device: str) -> VersionFacts:
    """What one collected device's `show version` says: its parse, or its text where the parser failed.

    The switch role and the platform column both read this, so a switch
    whose version Genie could not read is still the platform its text
    names, and still a switch. The text is read only where there is no
    parse: a parse that left a field empty is the device's own answer.
    """
    platform = platform_for(str(snapshot.devices.get(device, {}).get("os") or ""))
    if platform is None:
        return VersionFacts()
    parsed = snapshot.state(device, VERSION_COMMAND)
    if parsed is not None:
        return platform.version(parsed)
    return platform.version_from_text(snapshot.raw(device, VERSION_COMMAND))


def device_serials(snapshot: Snapshot, device: str) -> tuple[str, ...]:
    """The chassis serials one collected device reported, sorted; () for none."""
    declared_os = (snapshot.devices.get(device, {}).get("os") or "").lower()
    platform = platform_for(declared_os)
    if not platform:
        return ()
    serials = platform.serials(
        snapshot.state(device, VERSION_COMMAND),
        snapshot.state(device, platform.inventory_command),
    )
    if serials:
        return serials
    # No parse, or a parse without the serial: the redacted text of the same
    # command is on disk whatever Genie made of it.
    return platform.serials_from_text(snapshot.raw(device, platform.inventory_command))
