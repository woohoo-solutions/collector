"""One description per operating system DiscoNet can read.

Everything that differs between platforms and is not a command in
`commands.yaml` lives here: what the document calls the OS, how the diagram
colours it, how its interface names abbreviate, how to recognise it at login,
what a session needs before it stops paginating, and where `show version`
puts the software version and the chassis. Every other module asks this one;
none of them names an OS.

Adding an OS is adding one `Platform` below and a block in `commands.yaml`.
If another module wants an `if os == ...`, the fact it would branch on
belongs here instead — a test enforces that no other module holds the key
of a platform as a string literal.

Nothing here reads a snapshot, opens a connection or imports the rest of the
tool, so `naming.py`, `diagram.py` and `collector.py` can all depend on it
without depending on each other.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Mapping


@dataclass(frozen=True)
class VersionFacts:
    """What `show version` says about the device, in DiscoNet's own words."""

    software: str = ""
    platform: str = ""
    hostname: str = ""
    # The fabric a switch belongs to, where its own image says so: a Nexus
    # running the ACI image is a leaf or spine whose configuration lives on
    # the controller, and the document must say that rather than describe
    # the switch as if it stood alone. Empty for a device that stands alone.
    fabric: str = ""


def _fabric_in(text: str, markers: Mapping[str, str]) -> str:
    """The fabric a marker in `text` names, or "" for none."""
    lowered = (text or "").lower()
    for marker, fabric in markers.items():
        if marker in lowered:
            return fabric
    return ""


def _iosxe_version(parsed: Mapping[str, Any]) -> VersionFacts:
    version = parsed.get("version") or {}
    if not isinstance(version, Mapping):
        version = {}
    return VersionFacts(
        software=str(version.get("version") or ""),
        platform=str(
            version.get("platform") or version.get("chassis") or version.get("rtr_type") or ""
        ),
        hostname=str(version.get("hostname") or ""),
    )


# The lines of an IOS-XE `show version` the parse's fields come from, for a
# release whose text the parser fails on. The banner names the platform as
# Genie reads it, "Catalyst L3 Switch" or "ASR1000", with the 3.x releases'
# "IOS-XE Software," between; the version is the banner's, as in the parse.
_IOSXE_BANNER = re.compile(
    r"^Cisco IOS Software(?: \[[^\]]*\])?,(?: IOS-XE Software,)? (?P<platform>.+?) Software "
    r"\([^)]*\),? Version (?P<version>[^\s,]+)",
    re.MULTILINE,
)
_IOSXE_CHASSIS = re.compile(r"^cisco (?P<chassis>\S+) \([^)]*\) processor", re.MULTILINE | re.IGNORECASE)
_IOSXE_UPTIME = re.compile(r"^(?P<hostname>\S+) uptime is ", re.MULTILINE)


def _iosxe_version_text(text: str) -> VersionFacts:
    """Software, platform and hostname out of an IOS-XE `show version`'s text."""
    banner = _IOSXE_BANNER.search(text)
    chassis = _IOSXE_CHASSIS.search(text)
    uptime = _IOSXE_UPTIME.search(text)
    return VersionFacts(
        software=banner.group("version") if banner else "",
        platform=(banner.group("platform") if banner else "") or (chassis.group("chassis") if chassis else ""),
        hostname=uptime.group("hostname") if uptime else "",
    )


def _iosxr_version(parsed: Mapping[str, Any]) -> VersionFacts:
    return VersionFacts(
        software=str(parsed.get("software_version") or ""),
        platform=str(parsed.get("device_family") or parsed.get("chassis_detail") or ""),
        hostname=str(parsed.get("hostname") or ""),
    )


# The image file names the mode a Nexus 9000 runs in. A standalone switch
# boots `nxos.9.3.8.bin` or `nxos64-cs.10.2.5.M.bin`; a fabric member boots
# `aci-n9000-dk9.15.2.3g.bin`. That is a literal in the device's own output,
# not an inference from a version number.
NXOS_FABRIC_MARKERS: Mapping[str, str] = {"aci-n9000": "ACI"}


def _nxos_version(parsed: Mapping[str, Any]) -> VersionFacts:
    """Genie's NX-OS parser nests everything under `platform`."""
    platform = parsed.get("platform") if isinstance(parsed.get("platform"), Mapping) else {}
    software = platform.get("software") if isinstance(platform.get("software"), Mapping) else {}
    hardware = platform.get("hardware") if isinstance(platform.get("hardware"), Mapping) else {}
    images = " ".join(
        str(software.get(key) or "") for key in ("system_image_file", "kickstart_image_file")
    )
    return VersionFacts(
        software=str(software.get("system_version") or platform.get("system_version") or ""),
        platform=str(hardware.get("model") or hardware.get("chassis") or ""),
        hostname=str(hardware.get("device_name") or ""),
        fabric=_fabric_in(images, NXOS_FABRIC_MARKERS),
    )


# --- chassis serials ----------------------------------------------------
#
# A device's identity is the set of chassis it is made of. One box has one
# serial; a stack or a virtual chassis has one per member; a firewall pair
# has two boxes with one hostname, and a multi-context firewall one box with
# several. The set is read from `show version` and the inventory, chassis
# level only: a line card's serial changes when the card is replaced, and a
# device does not become another device when it does.

_NO_SERIAL = {"", "n/a", "na", "none", "unknown", "unspecified", "not available", "-"}
# A virtual or white-box chassis prints zeros where a serial would be, and
# every such box printing the same zeros was one serial: the second was
# folded into the first as its alias, its links and its facts with it.
_ZEROS = re.compile(r"0+")


def _clean_serials(values: Iterable[Any]) -> tuple[str, ...]:
    found = {str(value or "").strip().upper() for value in values}
    return tuple(sorted(s for s in found if s.lower() not in _NO_SERIAL and not _ZEROS.fullmatch(s)))


def _serials_under(data: Any, key: str) -> list[str]:
    """Every value of `key` in a parse, at any depth."""
    out: list[str] = []
    if isinstance(data, Mapping):
        if key in data and isinstance(data[key], (str, int)):
            out.append(str(data[key]))
        for value in data.values():
            out.extend(_serials_under(value, key))
    elif isinstance(data, list):
        for item in data:
            out.extend(_serials_under(item, key))
    return out


def _iosxe_serials(version: Mapping[str, Any] | None, inventory: Mapping[str, Any] | None) -> tuple[str, ...]:
    """The chassis serial, and every stack member's under the inventory's `main`."""
    found: list[str] = []
    block = (version or {}).get("version") if isinstance(version, Mapping) else None
    if isinstance(block, Mapping):
        found.extend(str(block.get(k) or "") for k in ("chassis_sn", "system_sn"))
    main = (inventory or {}).get("main") if isinstance(inventory, Mapping) else None
    found.extend(_serials_under(main, "sn"))
    return _clean_serials(found)


# Words that make a part a part, even when its description says chassis: an
# NCS 5500's fan tray is described in terms of the chassis it cools.
_PART_WORDS = ("fan", "power", "supply", "tray", "card", "module", "processor", "psu", "pem",
               "fabric", "filter", "controller", "shelf")


def chassis_rank(name: Any, descr: Any) -> int:
    """How surely an inventory entry is the chassis: 2 by name, 1 by description, 0 not.

    The name decides first: IOS-XR's `Rack 0`, classic IOS-XR's
    `chassis <PID>`, the `Chassis` entry most platforms print. A name or a
    description that says chassis counts only on a part that names no fan,
    power supply, tray or card: `Chassis 1 Fan Tray` is a fan tray.
    """
    name, descr = str(name or "").strip().lower(), str(descr or "").lower()
    if name.startswith("rack ") or name == "chassis":
        return 2
    if name.startswith("chassis ") and not any(word in name for word in _PART_WORDS):
        return 2
    if "chassis" in descr and not any(word in f"{name} {descr}" for word in _PART_WORDS):
        return 1
    return 0


def _iosxr_serials(version: Mapping[str, Any] | None, inventory: Mapping[str, Any] | None) -> tuple[str, ...]:
    """The rack entries of the inventory: IOS-XR's `show version` names no serial."""
    ranked: dict[int, list[str]] = {1: [], 2: []}
    modules = (inventory or {}).get("module_name") if isinstance(inventory, Mapping) else None
    for name, part in (modules or {}).items() if isinstance(modules, Mapping) else []:
        if not isinstance(part, Mapping):
            continue
        rank = chassis_rank(name, part.get("descr"))
        if rank:
            ranked[rank].append(str(part.get("sn") or ""))
    # Every rack of a multi-rack system, by name; a description only where no
    # entry is named as a rack.
    return _clean_serials(ranked[2] or ranked[1])


def _nxos_serials(version: Mapping[str, Any] | None, inventory: Mapping[str, Any] | None) -> tuple[str, ...]:
    found: list[str] = []
    platform = (version or {}).get("platform") if isinstance(version, Mapping) else None
    hardware = platform.get("hardware") if isinstance(platform, Mapping) else None
    if isinstance(hardware, Mapping):
        found.append(str(hardware.get("processor_board_id") or ""))
    names = (inventory or {}).get("name") if isinstance(inventory, Mapping) else None
    for name, part in (names or {}).items() if isinstance(names, Mapping) else []:
        if isinstance(part, Mapping) and "chassis" in str(name).lower():
            found.append(str(part.get("serial_number") or ""))
    return _clean_serials(found)


def _junos_serials(version: Mapping[str, Any] | None, inventory: Mapping[str, Any] | None) -> tuple[str, ...]:
    """The chassis's own serial from `show chassis hardware`, not its modules'."""
    chassis = None
    if isinstance(inventory, Mapping):
        info = inventory.get("chassis-inventory")
        chassis = info.get("chassis") if isinstance(info, Mapping) else None
    if isinstance(chassis, Mapping):
        return _clean_serials([chassis.get("serial-number")])
    return ()


# `show chassis hardware` as text: `Chassis  JN12A3B4C5D6  MX10003`, with a
# revision and a part number in between on some platforms. Only the line
# that opens with `Chassis`: the modules under it have serials of their own.
_JUNOS_CHASSIS_LINE = re.compile(
    r"^Chassis\s+(?:REV\s+\S+\s+)?(?:\d{3}-\d{6}\s+)?(?P<serial>[A-Za-z0-9]{6,})\s+\S"
)


def _junos_serials_text(text: str) -> tuple[str, ...]:
    """The chassis serial from the text of `show chassis hardware`.

    Genie's parser for the command has failed on every release that met this
    tool, so the text is the reading that actually happens. A virtual chassis
    prints one `Chassis` line per member and is the set of them.
    """
    found = [m.group("serial") for line in text.splitlines() if (m := _JUNOS_CHASSIS_LINE.match(line))]
    return _clean_serials(found)


def _junos_version(parsed: Mapping[str, Any]) -> VersionFacts:
    """Genie's Junos parsers keep the XML tag names, hyphens and all."""
    info = parsed.get("software-information") or {}
    if not isinstance(info, Mapping):
        info = {}
    return VersionFacts(
        software=str(info.get("junos-version") or ""),
        platform=str(info.get("product-model") or ""),
        hostname=str(info.get("host-name") or ""),
    )


def _junos_addresses(parsed: Mapping[str, Any], family: str) -> dict[str, list[str]]:
    """`interface -> ['10.0.12.1/30']` out of `show interfaces terse`.

    Addresses sit on the logical unit (`ge-0/0/0.0`), under `protocol` and
    then `inet` or `inet6`, keyed by the address itself. A loopback host
    address prints as `10.0.0.1 --> 0/0` with no mask: the `0/0` is Junos
    saying it is a host address, so the host mask is what the device meant.
    """
    protocol = {"ipv4": "inet", "ipv6": "inet6"}.get(family, family)
    found: dict[str, list[str]] = {}
    for interface, data in parsed.items():
        if not isinstance(data, Mapping):
            continue
        block = (data.get("protocol") or {}).get(protocol) if isinstance(data.get("protocol"), Mapping) else None
        if not isinstance(block, Mapping):
            continue
        addresses: list[str] = []
        for key, detail in block.items():
            detail = detail if isinstance(detail, Mapping) else {}
            address = str(detail.get("local") or key).strip()
            bare = address.split("/")[0]
            try:
                parsed_address = ipaddress.ip_address(bare)
            except ValueError:
                continue
            if parsed_address.is_link_local or parsed_address.is_loopback:
                continue
            # The inet6 address of a loopback unit prints with no mask and no
            # `--> 0/0` at all; on a loopback a bare address is a host address.
            if "/" not in address and (
                str(detail.get("remote") or "") == "0/0" or str(interface).startswith("lo0")
            ):
                address = f"{bare}/{parsed_address.max_prefixlen}"
            addresses.append(address)
        if addresses:
            found[str(interface)] = sorted(set(addresses))
    return found


# --- the IP MTU ---------------------------------------------------------
#
# The largest IP packet an interface sends, which every OS states alike. The
# interface MTU is not: IOS-XR and Junos count the 14-byte Ethernet header in
# it and IOS-XE does not, so one interface MTU at both ends of a mixed link
# is two IP MTUs, and 1514 at one end against 1500 at the other can be none.
# Each reader takes the IP MTU alone, out of the table its OS prints it in.


def _whole_mtu(value: Any) -> int | None:
    """An MTU as a positive whole number, or None where the parse holds none."""
    if isinstance(value, bool):
        return None
    text = str(value if value is not None else "").strip()
    return int(text) if text.isdigit() and int(text) > 0 else None


def _mappings(value: Any) -> list[Mapping[str, Any]]:
    """The entries of a Junos list, which a parse writes as a mapping where there is one."""
    rows = [value] if isinstance(value, Mapping) else (value if isinstance(value, list) else [])
    return [row for row in rows if isinstance(row, Mapping)]


def _iosxe_ip_mtu(parsed: Mapping[str, Any]) -> dict[str, int]:
    """`interface -> IP MTU` out of `show ip interface`, whose `MTU is 1500 bytes` is the IP MTU."""
    found: dict[str, int] = {}
    for interface, data in parsed.items():
        mtu = _whole_mtu(data.get("mtu")) if isinstance(data, Mapping) else None
        if mtu is not None:
            found[str(interface)] = mtu
    return found


def _iosxr_ip_mtu(parsed: Mapping[str, Any]) -> dict[str, int]:
    """`interface -> IP MTU` out of `show ipv4 vrf all interface`.

    The line reads `MTU is 1514 (1500 is available to IP)`. The first number
    is the interface's, header included, and Genie keeps it as `mtu`; the
    one available to IP is the IP MTU, `mtu_available`, and only it is read.
    """
    found: dict[str, int] = {}
    for interface, data in parsed.items():
        block = data.get("ipv4") if isinstance(data, Mapping) else None
        mtu = _whole_mtu(block.get("mtu_available")) if isinstance(block, Mapping) else None
        if mtu is not None:
            found[str(interface)] = mtu
    return found


def _nxos_ip_mtu(parsed: Mapping[str, Any]) -> dict[str, int]:
    """`interface -> IP MTU` out of `show ip interface vrf all`, which prints `IP MTU: 1500 bytes`."""
    found: dict[str, int] = {}
    for interface, data in parsed.items():
        mtu = _whole_mtu(data.get("ip_mtu")) if isinstance(data, Mapping) else None
        if mtu is not None:
            found[str(interface)] = mtu
    return found


def _junos_ip_mtu(parsed: Mapping[str, Any]) -> dict[str, int]:
    """`logical interface -> IP MTU` out of `show interfaces`.

    `Protocol inet, MTU: 1500` under `ge-0/0/0.0` is the IP MTU, and an
    address sits on that unit. The physical interface's `Link-level type:
    Ethernet, MTU: 1514` counts the header, as IOS-XR's interface MTU does,
    and is not read; nor is the `mpls` family's, which leaves room for labels.

    Genie 26.9 files a unit's families only on a `Generation:` line, which
    the plain table does not print: its parse has every `address-family`
    list empty, as Genie's own expected parses of the table do, and the
    text below is what is read.
    """
    found: dict[str, int] = {}
    info = parsed.get("interface-information")
    ports = info.get("physical-interface") if isinstance(info, Mapping) else None
    for port in _mappings(ports):
        for unit in _mappings(port.get("logical-interface")):
            for family in _mappings(unit.get("address-family")):
                if str(family.get("address-family-name") or "").lower() != "inet":
                    continue
                mtu = _whole_mtu(family.get("mtu"))
                if mtu is not None and unit.get("name"):
                    found[str(unit["name"])] = mtu
    return found


# `show interfaces` as Junos prints it: a `Logical interface ge-0/0/0.0` line
# opens each unit, and its `Protocol inet, MTU: 1500` line is the IP MTU. A
# `Physical interface:` line closes the unit before it, so the port's own
# `MTU: 1514` never lands on one.
_JUNOS_PORT_LINE = re.compile(r"^\s*Physical interface:\s")
_JUNOS_UNIT_LINE = re.compile(r"^\s*Logical interface\s+(?P<name>\S+)")
_JUNOS_INET_MTU = re.compile(r"^\s*Protocol\s+inet,\s+MTU:\s+(?P<mtu>[^,\s]+)")


def _junos_ip_mtu_text(text: str) -> dict[str, int]:
    """`logical interface -> IP MTU` out of the text of `show interfaces`; `Unlimited` is none."""
    found: dict[str, int] = {}
    unit = ""
    for line in text.splitlines():
        if _JUNOS_PORT_LINE.match(line):
            unit = ""
        elif match := _JUNOS_UNIT_LINE.match(line):
            unit = match.group("name")
        elif unit and (match := _JUNOS_INET_MTU.match(line)):
            mtu = _whole_mtu(match.group("mtu"))
            if mtu is not None:
                found.setdefault(unit, mtu)
    return found


@dataclass(frozen=True)
class Platform:
    """One operating system, as the rest of the tool needs to know it."""

    key: str                       # the testbed's `os:` value and the commands.yaml block
    label: str                     # what the document calls it: IOS-XE
    vendor: str                    # Cisco
    examples: str                  # the hardware an engineer would recognise it by
    short: str                     # the diagram accent and the wizard's quirk-key suffix
    colour_light: str              # accent colour on the light page
    colour_dark: str               # accent colour on the dark page
    # Abbreviation -> full interface name. The same two letters mean different
    # things on different platforms, which is why this is per OS.
    abbreviations: Mapping[str, str]
    # Exec-mode commands sent once per session so output is not paginated.
    # Session-local and configuration-neutral; constants here, never anything
    # a testbed can reach.
    session_setup: tuple[str, ...]
    # Whether the OS has an `enable` privilege step at all. IOS-XR logs
    # straight into a privileged shell; `double_enable` is meaningless there,
    # and finalize drops it from a device it turns out to be XR.
    has_enable: bool
    # Keys a device of this OS collects correctly under, so a testbed that
    # declares one of them is not wrong and is not logged into again. Classic
    # IOS reads through the IOS-XE allowlist and parsers; a `show version`
    # that names it under an `iosxe` declaration settles nothing.
    stands_in_for: tuple[str, ...] = ()
    # How the login dialog proves the OS. A prompt only this OS prints beats a
    # substring in the version banner; either is enough on its own.
    prompts: tuple[re.Pattern[str], ...] = ()
    version_markers: tuple[str, ...] = ()
    # Substrings of the SSH server banner that suggest the OS. A suggestion:
    # `os_hint` in inventory.py says why it is never acted on unattended.
    ssh_banner_hints: tuple[str, ...] = ()
    # Commands the address inventory reads, by family. The full forms carry
    # the prefix length; the brief forms are a maskless fallback.
    address_commands: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    arp_command: str = ""
    # The IPv6 neighbour table, as this OS spells the command. Cisco IOS-XE,
    # IOS-XR and Junos agree; NX-OS does not.
    nd_command: str = "show ipv6 neighbors"
    # Substrings of `show version` — parsed or raw — that name a fabric the
    # device is a member of, and what the document calls that fabric. Read
    # from the raw text too, because a fabric-mode image can print a `show
    # version` the standalone parser does not understand.
    fabric_markers: Mapping[str, str] = field(default_factory=dict)
    version_facts: Callable[[Mapping[str, Any]], VersionFacts] = lambda parsed: VersionFacts()
    # The same facts out of `show version`'s text, for a release whose text
    # the parser fails on. Without it a switch whose version Genie could not
    # read has no platform and no switch role, though the text names both.
    version_text: Callable[[str], VersionFacts] = lambda text: VersionFacts()
    # The fixed-configuration chassis of this OS: patterns matched, from its
    # start and ignoring case, against the chassis PID the inventory names
    # (on Junos, the model `show chassis hardware` describes the chassis
    # as). Every port of one sits on its one board, which fails with the box
    # and never alone, so no line card is read from its interface names. A
    # model not listed is read as a chassis with cards, by its names.
    fixed_chassis: tuple[str, ...] = ()
    # The command whose parse names the chassis, and the reader that takes
    # the chassis serials out of it and out of `show version`.
    inventory_command: str = "show inventory"
    serial_facts: Callable[[Mapping[str, Any] | None, Mapping[str, Any] | None], tuple[str, ...]] = (
        lambda version, inventory: ()
    )
    # The same serials out of the inventory command's text, for a platform
    # whose parser fails on it. Without this a chassis reached under several
    # addresses is several nodes, because nothing else says it is one box.
    serial_text: Callable[[str], tuple[str, ...]] = lambda text: ()
    # The running configuration, as this OS names it. Raw only, redacted, and
    # what the hostname, the configuration excerpts and the QoS attachments
    # are read from.
    config_command: str = "show running-config"
    # The stanza that declares a VRF in that configuration, with the name in
    # a `name` group: what the per-VRF tables are rendered for. None where
    # the OS reads every VRF in one table and needs no per-VRF command.
    vrf_declaration: re.Pattern[str] | None = None
    # A BGP process anywhere in the configuration, VRFs included. Its
    # absence from a captured configuration says the device runs BGP in no
    # address family, including one whose summary was not collected. None
    # where DiscoNet knows no such line: then nothing is concluded from it.
    bgp_declaration: re.Pattern[str] | None = None
    # Where the configuration states a VRF's static routes, on an OS whose
    # static-route commands list the default VRF's alone: `ip-route-vrf` for
    # `ip route vrf X ...` and `ipv6 route vrf X ...` lines, `router-static`
    # for the `vrf X` blocks of `router static`. "" where the commands list
    # every VRF already, or where DiscoNet reads no such syntax.
    vrf_static_config: str = ""
    # How the configuration states static routes, every VRF's, for the
    # reader that types them (`disconet.routing.configured_statics`):
    # `ip-route` for IOS-XE and IOS `ip route` / `ipv6 route [vrf X] ...`,
    # `router-static` for IOS-XR, `ip-route-prefix` for NX-OS `ip route
    # <p>/<len>` at the top level and under `vrf context`, `routing-options`
    # for Junos `static` blocks. "" where DiscoNet reads no such syntax.
    static_config: str = ""
    # Whether the VRF table states each VRF's route targets, as an empty list
    # where none is set. NX-OS's names none: there they are read from the
    # `vrf context` stanzas, and only where the configuration was captured.
    vrf_table_states_targets: bool = True
    # Whether the VRF table states each VRF's interfaces. NX-OS's names none:
    # there they are read from `show vrf all interface`, and a VRF with none
    # is only known to have none where that table was read.
    vrf_table_states_interfaces: bool = True
    # Interface types that are never abbreviated and never expanded: Junos
    # writes `ge-0/0/0` and nothing else. These are what makes such a name
    # recognisable as an interface at all, since the tables above cannot.
    interface_types: tuple[str, ...] = ()
    # Mbit/s per type, for the types above. A type with no entry has no rate
    # the name can vouch for.
    interface_rates: Mapping[str, int] = field(default_factory=dict)
    # Type prefixes, followed by a digit, that are a loopback (`lo0`) or some
    # other logical construct rather than a port.
    loopback_types: tuple[str, ...] = ()
    logical_types: tuple[str, ...] = ()
    # Junos puts the address on unit 0 of the port LLDP names: `ge-0/0/0.0`
    # and `ge-0/0/0` are one interface for the purpose of matching an edge.
    unit_zero_is_port: bool = False
    # A reader for the address inventory where the parse is not shaped like
    # the Cisco ones: `(parsed, family) -> {interface: [address/prefix]}`.
    address_reader: Callable[[Mapping[str, Any], str], dict[str, list[str]]] | None = None
    # The interface table that states each interface's IP MTU, one this OS
    # already answers on every collection, and the reader that takes the IP
    # MTU out of its parse: `parsed -> {interface: IP MTU}`. Empty where the
    # IP MTU is not read on this OS: a link with an end on it is then left
    # out of the comparison, and said to be.
    ip_mtu_command: str = ""
    ip_mtu_reader: Callable[[Mapping[str, Any]], dict[str, int]] | None = None
    # The same out of that table's text, for an OS whose Genie parser leaves
    # the IP MTU out of the parse: Junos's does, on every unit.
    ip_mtu_text: Callable[[str], dict[str, int]] = lambda text: {}
    # Hostname suffixes a device wears at login but not in its protocols: a
    # dual-RE Junos box logs in as `X-re0` and is `X` to IS-IS and LDP. Two
    # names that differ only by one of these are one device.
    hostname_suffixes: tuple[str, ...] = ()
    # The hostname a box carries before anybody named it (`Router`,
    # `Switch`, IOS-XR's `ios`): what a neighbour reports for a device left
    # at its factory setting. It names nobody, and registered as a hostname
    # every "switch" and "router" in the tool's own instructions became it.
    factory_hostnames: tuple[str, ...] = ()
    # Interface types whose addresses never make an edge: internal fabric
    # and RE-to-RE links, and out-of-band management. Their addresses are
    # private, repeated on every box, and shared over a switch the document
    # is not about; read as evidence they draw links that do not exist.
    internal_types: tuple[str, ...] = ()
    # Whole interface names that are out-of-band on this OS, where a type
    # prefix would take the front-panel ports with it: `GigabitEthernet0`
    # is management on IOS-XE and `GigabitEthernet0/0/1` is not. A name is
    # read on its own OS only: what is management on one is a front-panel
    # port on another.
    internal_names: tuple[str, ...] = ()
    # The VRFs the OS itself creates for its management port. An interface
    # in one is out-of-band whatever it is called. A VRF the operator named
    # is not read for what its name seems to say.
    management_vrfs: tuple[str, ...] = ()
    # Words this OS's configuration puts where a name goes that are its own,
    # not anybody's naming convention: the built-in AAA server groups
    # (`group tacacs+`), a firewall's factory interface names and the names
    # a switch gives its factory VLANs (VLAN 1 `default`, and on Catalyst
    # 1002-1005 `fddi-default` and the rest). They name nobody, so they are
    # never pseudonymised as a name: VLAN 1's `default` learned as one made
    # every `default` in the facts, the global table's VRF and the AAA
    # method list among them, a placeholder. The catch-all class of a
    # Cisco policy map, `class-default`, is the platform's too.
    builtin_names: tuple[str, ...] = ()
    # `logical name -> interface`, read from the parse of the first IPv4
    # address command, for an OS whose tables name interfaces by something
    # other than the port: ASA keys its ARP table by nameif.
    interface_aliases: Callable[[Mapping[str, Any]], dict[str, str]] | None = None
    # Full names another platform's spelling puts on this OS's ports, by
    # their lowercase form, with the name this OS gives the port. Genie's IOS
    # XR parsers expand `Te0/0/0/1` to IOS XE's `TenGigabitEthernet0/0/0/1`
    # in the neighbour and adjacency tables, where the box itself, and CDP
    # and its address table, say `TenGigE0/0/0/1`: one port, two names, and
    # two edges in the topology for the one cable.
    respellings: Mapping[str, str] = field(default_factory=dict)
    # What the diagram draws this OS as: a router, a switch or a firewall.
    node_kind: str = "router"
    # Commands this platform reads from the redacted text when Genie has no
    # parser or its parser fails. Genie failing on one is not a collection
    # gap: the output is on disk and was read.
    text_parsed: tuple[str, ...] = ()
    # How the running configuration is read for the coverage appendix, which
    # says what the configuration states that no reader of this tool reads.
    # `config_nested` marks a braces syntax that is flattened into paths
    # rather than split into indented stanzas; `config_family_depth` names the
    # top-level containers whose children are the families worth counting
    # apart (`protocols isis` is a family, `protocols` is not), in either
    # syntax; and `config_families` maps the opening of a stanza to the
    # coverage key that reads it — a feature key from the allowlist, or one of
    # the fixed keys for what is always collected (identity, physical). The
    # longest prefix wins. A family absent from the map is configuration this
    # tool does not read, and the appendix says so; one mapped to "" is too,
    # named where a shorter prefix's reader would otherwise claim it. The map
    # is a claim about the readers and lives here because it is a claim about
    # this OS's syntax.
    config_nested: bool = False
    config_family_depth: tuple[str, ...] = ()
    config_families: tuple[tuple[str, str], ...] = ()
    # The statements under an `interface` stanza that put the interface into
    # IS-IS, on a platform whose configuration says so per interface. Read
    # only where no IS-IS interface command answered: a snapshot of an
    # IOS-XE estate taken before `show clns interface` was collected.
    isis_interface_config: tuple[str, ...] = ()
    # Where the configuration turns IS-IS hello padding off, as this OS
    # spells it: under the interface (`isis_unpadded_interface`), under an
    # interface of the `router isis` process (`isis_unpadded_process_interface`)
    # or at the process for every interface (`isis_unpadded_process`). An
    # adjacency forms over an MTU mismatch when the larger end does not pad,
    # which is why the document reads it. All empty where it is not read.
    isis_unpadded_interface: tuple[str, ...] = ()
    isis_unpadded_process_interface: tuple[str, ...] = ()
    isis_unpadded_process: tuple[str, ...] = ()

    def version(self, parsed: Mapping[str, Any] | None) -> VersionFacts:
        """Software, chassis and hostname out of a `show version` parse."""
        if not isinstance(parsed, Mapping):
            return VersionFacts()
        return self.version_facts(parsed)

    def version_from_text(self, text: str | None) -> VersionFacts:
        """The same facts read from the raw text of `show version`; empty where it names none."""
        return self.version_text(text or "")

    def serials(
        self, version: Mapping[str, Any] | None, inventory: Mapping[str, Any] | None
    ) -> tuple[str, ...]:
        """The chassis serials that identify this device, sorted; () where none was printed."""
        try:
            return self.serial_facts(version, inventory)
        except (AttributeError, TypeError, ValueError):
            return ()

    def serials_from_text(self, text: str | None) -> tuple[str, ...]:
        """The chassis serials read from the inventory command's raw text; () for none."""
        try:
            return self.serial_text(text or "")
        except (AttributeError, TypeError, ValueError):
            return ()

    def ip_mtus(self, parsed: Mapping[str, Any] | None, text: str | None = None) -> dict[str, int]:
        """`interface -> IP MTU` out of `ip_mtu_command`: its parse, then its text where the parse states none."""
        found = dict(self.ip_mtu_reader(parsed)) if self.ip_mtu_reader and isinstance(parsed, Mapping) else {}
        for interface, mtu in self.ip_mtu_text(text or "").items():
            found.setdefault(interface, mtu)
        return found

    def is_fixed_chassis(self, pid: str | None) -> bool:
        """Is this chassis PID one of this OS's fixed-configuration models?"""
        text = str(pid or "").strip()
        return bool(text) and any(re.match(pattern, text, re.IGNORECASE) for pattern in self.fixed_chassis)

    def fabric(self, parsed: Mapping[str, Any] | None, raw: str = "") -> str:
        """The fabric this device says it belongs to, or "" for a standalone device."""
        found = self.version(parsed).fabric
        if found:
            return found
        return _fabric_in(raw, self.fabric_markers)

    def prompt_match(self, dialog: str) -> re.Match[str] | None:
        for pattern in self.prompts:
            match = pattern.search(dialog)
            if match:
                return match
        return None


IOSXE = Platform(
    key="iosxe",
    label="IOS-XE",
    vendor="Cisco",
    examples="ISR, ASR1k, CSR1000v, Catalyst 8000, ASR920",
    short="xe",
    colour_light="#2563eb",
    colour_dark="#60a5fa",
    abbreviations={
        "fa": "FastEthernet",
        "gi": "GigabitEthernet",
        "tw": "TwoGigabitEthernet",
        "fi": "FiveGigabitEthernet",
        "te": "TenGigabitEthernet",
        # A Catalyst 9500 prints `TwentyFiveGigE1/0/1` and `HundredGigE1/0/1`;
        # the long spelling of the hundred-gig port is IOS-XR's.
        "twe": "TwentyFiveGigE",
        "fo": "FortyGigabitEthernet",
        "hu": "HundredGigE",
        "eth": "Ethernet",
        "et": "Ethernet",
        "po": "Port-channel",
        "lo": "Loopback",
        "se": "Serial",
        "tu": "Tunnel",
        "vl": "Vlan",
        "nu": "Null",
        "ma": "Management",
        "mg": "Management",
        # `show isis neighbors` writes a bridge-domain interface as `BD10`.
        "bd": "BDI",
        "bdi": "BDI",
        # A Catalyst 9000's application-hosting and Bluetooth ports, as its
        # `show interfaces description` writes them.
        "ap": "AppGigabitEthernet",
        "bl": "Bluetooth",
        # An ISR's WAN interfaces, as the same table writes them.
        "mu": "Multilink",
        "vi": "Virtual-Access",
        "di": "Dialer",
        "ce": "Cellular",
    },
    session_setup=("terminal length 0", "terminal width 0"),
    has_enable=True,
    # IOS-XE has no prompt of its own: `hostname#` is what every Cisco prints.
    # The version banner is the only thing that names it.
    # Both spellings a `show version` has used: "Cisco IOS XE Software" from
    # 16.x on, "IOS-XE Software" on the 3.x releases. The bare "Cisco IOS
    # Software" that every IOS-XE also prints is classic IOS's marker below,
    # and classic IOS is registered last, so a banner naming XE anywhere is
    # XE and a banner that never does is IOS.
    version_markers=("cisco ios xe software", "ios-xe software", "iosxe"),
    ssh_banner_hints=("cisco-1.25",),
    internal_types=("MgmtEth", "Management", "mgmt"),
    # The out-of-band port on an ISR or an ASR 1000: `GigabitEthernet0`,
    # in VRF Mgmt-intf, with the management /24 on it, which four such
    # routers read as a shared subnet the document was not about. A
    # Catalyst 9000, 3850 or 3650 calls its own `GigabitEthernet0/0`, in
    # VRF Mgmt-vrf; an IOS-XE router numbers its front-panel ports in three
    # parts, `GigabitEthernet0/0/0`.
    internal_names=("GigabitEthernet0", "GigabitEthernet0/0"),
    # A Catalyst 4500's management port is `FastEthernet1`, in mgmtVrf.
    management_vrfs=("Mgmt-intf", "Mgmt-vrf", "mgmtVrf"),
    factory_hostnames=("Router", "Switch"),
    builtin_names=(
        "tacacs+", "radius", "ldap", "class-default",
        "default", "fddi-default", "token-ring-default", "fddinet-default", "trnet-default",
    ),
    address_commands={
        "ipv4": ("show ip interface",),
        "ipv6": ("show ipv6 interface",),
        "brief_ipv4": ("show ip interface brief",),
        # Genie's IOS-XE `show ipv6 interface` schema makes the per-interface
        # `ipv6` key mandatory, so one interface without an IPv6 address fails
        # the whole parse and the device loses its IPv6 addressing entirely.
        # The brief form carries no mask but survives that, exactly as the
        # IPv4 brief form backs up `show ip interface`.
        "brief_ipv6": ("show ipv6 interface brief",),
    },
    arp_command="show ip arp",
    ip_mtu_command="show ip interface",
    ip_mtu_reader=_iosxe_ip_mtu,
    vrf_declaration=re.compile(r"^(?:vrf definition|ip vrf)\s+(?P<name>\S+)\s*$", re.MULTILINE),
    bgp_declaration=re.compile(r"^router bgp \d", re.MULTILINE),
    vrf_static_config="ip-route-vrf",
    static_config="ip-route",
    isis_interface_config=("ip router isis", "ipv6 router isis"),
    isis_unpadded_interface=("no isis hello padding",),
    isis_unpadded_process=("no hello padding",),
    version_facts=_iosxe_version,
    version_text=_iosxe_version_text,
    serial_facts=_iosxe_serials,
    # The ASR 920 and the NCS 520; the Metro Ethernet and Catalyst access
    # switches, which a stack makes several chassis of (see
    # hardware.fixed_chassis); the Catalyst 9500; the ASR 1001-X and 1002-X;
    # the ISR 1100 and 4000. Classic IOS inherits the table: the same boxes
    # run either OS by release.
    fixed_chassis=(
        r"ASR-920", r"N520-", r"ME-3[468]00", r"C9200", r"C9300", r"C9500",
        r"WS-C(?:2960|3560|3650|3750|3850)", r"ASR100[12]-X\b", r"C11\d\d", r"ISR4\d{3}",
    ),
    # The IPv6 side of the IGPs and of multicast is read from the text on
    # every platform, so Genie having no parser for one is not a gap.
    text_parsed=(
        "show ospfv3 neighbor", "show ospfv3 interface brief",
        "show isis neighbors detail", "show ipv6 pim neighbor", "show ipv6 mld groups",
        # Genie's parser takes no interface name with a hyphen in it, so a
        # Port-channel's IS-IS would be credited to the port printed before it.
        "show clns interface",
        "show isis database detail", "show ip ospf database router", "show ip ospf database network",
        # The switching readers take the text wherever Genie's parse fails
        # them, the detail form's schema being strict about fields an
        # older release does not print.
        "show spanning-tree detail",
    ),
    config_families=(
        ("hostname", "identity"),
        ("interface", "physical"),
        ("lldp", "physical"),
        ("cdp", "physical"),
        ("spanning-tree", "switching"),
        ("vlan", "switching"),
        ("vtp", "switching"),
        # G18: the global `port-channel load-balance`, as on NX-OS.
        ("port-channel", "lag"),
        ("router ospf", "ospf"),
        ("router ospfv3", "ospf"),
        ("router isis", "isis"),
        ("router bgp", "bgp"),
        ("ip route", "routing"),
        ("ipv6 route", "routing"),
        ("mpls ldp", "ldp"),
        ("mpls ip", "ldp"),
        ("mpls label", "ldp"),
        ("segment-routing", "sr"),
        # SRv6 and SR-TE open stanzas of their own beside SR-MPLS's, and the
        # SR-MPLS reader reads neither. No reader of this tool reads an SR-TE
        # policy yet.
        ("segment-routing srv6", "srv6"),
        ("segment-routing traffic-eng", ""),
        ("mpls traffic-eng", "mplste"),
        ("vrf definition", "l3vpn"),
        ("ip vrf", "l3vpn"),
        # Read for the route targets a VRF's import and export maps set and
        # match (routepolicy.iosxe_vrf_policies); the rest of the route policy
        # is not documented.
        ("route-map", "l3vpn"),
        ("ip extcommunity-list", "l3vpn"),
        # The lists a route-map names, read whole (policy.iosxe_policies, G05).
        ("ip prefix-list", "bgp"),
        ("ipv6 prefix-list", "bgp"),
        ("ip community-list", "bgp"),
        ("l2vpn", "l2vpn"),
        ("bridge-domain", "l2vpn"),
        ("pseudowire-class", "l2vpn"),
        ("ip multicast-routing", "multicast"),
        # `ip multicast [vrf X] mpls mldp|source` (services.mvpn_configuration).
        ("ip multicast", "multicast"),
        ("ip pim", "multicast"),
        ("router pim", "multicast"),
        ("ptp", "ptp"),
        ("bfd-template", "bfd"),
        ("policy-map", "qos"),
        ("class-map", "qos"),
        ("ntp", "management"),
        ("aaa", "management"),
        ("tacacs", "management"),
        ("tacacs-server", "management"),
        ("radius", "management"),
        ("radius-server", "management"),
        ("ip tacacs", "management"),
        ("ip radius", "management"),
        ("username", "management"),
        ("line vty", "management"),
        ("ip ssh", "management"),
        ("ip http", "management"),
        ("netconf-yang", "management"),
        ("restconf", "management"),
        ("snmp-server", "management"),
        ("logging", "management"),
        ("flow exporter", "management"),
        ("flow monitor", "management"),
        ("ip flow-export", "management"),
        ("control-plane", "management"),
        # G17: read by the management residuals (management._residuals_iosxe),
        # or on the ignore list (statement_rules.IGNORED), which counts them
        # ignored by statement and read by stanza.
        ("archive", "management"),
        ("redundancy", "management"),
        ("line con", "management"),
        ("line aux", "management"),
        ("privilege", "management"),
        ("enable", "management"),
        ("ip domain", "management"),
        ("ip domain-name", "management"),
        ("ip domain-lookup", "management"),
        ("no ip domain", "management"),
        ("ip name-server", "management"),
        ("ip host", "management"),
        ("ip ftp", "management"),
        ("no ip http", "management"),
        ("no logging", "management"),
        ("login on-success", "management"),
        ("login on-failure", "management"),
        ("snmp", "management"),
        ("boot", "management"),
        ("clock", "management"),
        ("license", "management"),
        ("service", "management"),
        ("no service", "management"),
        # G12: read by opsconfig.read_ops_config. Narrow on purpose: `monitor
        # capture`, `monitor event-trace` and `ip sla <n>` operations are not read.
        ("monitor session", "management"),
        ("ip sla responder", "management"),
        # G08: access lists, read whole by acl.read_acls; `physical`, as the
        # interfaces they bind to: configuration only, always collected.
        ("ip access-list", "physical"),
        ("ipv6 access-list", "physical"),
        ("access-list", "physical"),
        # G16: IKE, IPsec, crypto maps, PKI trustpoints and remote-access
        # pools, read by cryptoconfig.read_crypto_config. `physical`, as G08's
        # access lists: configuration only, always collected; the `security`
        # feature is ASA/SRX show output. `crypto engine`, `crypto gkm` and
        # the rest stay unclaimed.
        ("crypto isakmp", "physical"),
        ("crypto ikev2", "physical"),
        ("crypto keyring", "physical"),
        ("crypto ipsec", "physical"),
        ("crypto map", "physical"),
        ("crypto dynamic-map", "physical"),
        ("crypto pki", "physical"),
        ("ip local pool", "physical"),
        # G22: authentication key chains, read by keychain.read_key_chains.
        # `physical`, as G08 and G16: configuration only, always collected.
        ("key chain", "physical"),
    ),
)

# Classic IOS: the Catalyst access layer (2960, 3560, 3750, 3850 before it
# moved to XE) and the older ISRs. It reads exactly like IOS-XE — Genie's
# `ios` parsers inherit the IOS-XE ones and the CLI is the same — so the
# entry is IOS-XE with its own key, name and banner. It is registered last:
# every IOS-XE `show version` also prints "Cisco IOS Software", so the bare
# marker may only decide once no platform naming XE has matched.
IOS = replace(
    IOSXE,
    key="ios",
    label="IOS",
    examples="Catalyst 2960, 3560, 3750, 3850, ISR G2",
    short="ios",
    colour_light="#0e7490",
    colour_dark="#22d3ee",
    version_markers=("cisco ios software",),
    # The SSH banner is the same `Cisco-1.25` as IOS-XE's, which the wizard
    # already reads as IOS-XE; finalize corrects the key from `show version`.
    ssh_banner_hints=(),
    # An ISR G2's `GigabitEthernet0/0` is its first front-panel port.
    internal_names=("GigabitEthernet0",),
    stands_in_for=(IOSXE.key,),
)

IOSXR = Platform(
    key="iosxr",
    label="IOS-XR",
    vendor="Cisco",
    examples="ASR9k, NCS540, NCS5500, XRv",
    short="xr",
    colour_light="#0d9488",
    colour_dark="#2dd4bf",
    abbreviations={
        "gi": "GigabitEthernet",
        "te": "TenGigE",
        "twe": "TwentyFiveGigE",
        # The adjacency tables write a 25G port `TF`, a 200G one `TH` and a
        # 400G one `FH`, as an NCS540 or an NCS5500 prints them.
        "tf": "TwentyFiveGigE",
        "fo": "FortyGigE",
        "hu": "HundredGigE",
        "th": "TwoHundredGigE",
        "fh": "FourHundredGigE",
        "be": "Bundle-Ether",
        "bundle-ether": "Bundle-Ether",
        "lo": "Loopback",
        "mg": "MgmtEth",
        "nu": "Null",
        "bv": "BVI",
        "tu": "Tunnel",
        "tt": "Tunnel-te",
        # `show interfaces description` writes the RP's timing port `PT` and
        # an IP tunnel `ti`.
        "pt": "PTP",
        "ti": "tunnel-ip",
    },
    respellings={
        "tengigabitethernet": "TenGigE",
        "twentyfivegigabitethernet": "TwentyFiveGigE",
        "fortygigabitethernet": "FortyGigE",
        "hundredgigabitethernet": "HundredGigE",
    },
    session_setup=("terminal length 0", "terminal width 0"),
    has_enable=False,
    # `RP/0/RP0/CPU0:hostname#` is unmistakably XR, and so is the sysadmin VM
    # a failed login sometimes lands in.
    prompts=(
        re.compile(r"(?:^|\s)(?:RP|RSP)/\d+/(?:RP|RSP)?\d*/CPU\d+:\S+[#>]", re.MULTILINE),
        re.compile(r"(?:^|\s)sysadmin-vm:\S+[#>]", re.MULTILINE),
    ),
    version_markers=("cisco ios xr software",),
    ssh_banner_hints=("cisco-2.0",),
    internal_types=("MgmtEth", "Management", "mgmt"),
    factory_hostnames=("ios",),
    builtin_names=("tacacs+", "radius", "class-default"),
    address_commands={
        "ipv4": ("show ipv4 vrf all interface",),
        # Every VRF's first, as for IPv4; the default VRF's alone where that
        # did not parse or was not collected.
        "ipv6": ("show ipv6 vrf all interface", "show ipv6 interface"),
        "brief_ipv4": ("show ipv4 interface brief",),
        "brief_ipv6": (),
    },
    arp_command="show arp detail",
    ip_mtu_command="show ipv4 vrf all interface",
    isis_unpadded_process_interface=("hello-padding disable",),
    ip_mtu_reader=_iosxr_ip_mtu,
    vrf_declaration=re.compile(r"^vrf\s+(?P<name>\S+)\s*$", re.MULTILINE),
    bgp_declaration=re.compile(r"^router bgp \d", re.MULTILINE),
    vrf_static_config="router-static",
    static_config="router-static",
    version_facts=_iosxr_version,
    serial_facts=_iosxr_serials,
    # The NCS 540; the NCS 5501, 5502 and 55A1; the NCS 57B1, 57C1 and 57D2;
    # the Cisco 8100 and 8200. Not the NCS 55A2 or 57C3, which take port
    # adapters, nor the ASR 9001, which takes modular port adapters.
    fixed_chassis=(r"N540", r"NCS-550[12]\b", r"NCS-55A1", r"NCS-57(?:B1|C1|D2)", r"8[12]\d\d-"),
    text_parsed=(
        "show ospfv3 neighbor", "show ospfv3 interface brief",
        "show isis adjacency detail", "show pim ipv6 neighbor", "show mld groups",
        "show isis database detail", "show ospf database router", "show ospf database network",
        # Genie has no XR parser for either; the multicast readers take the
        # neighbours and the (*,G) and (S,G) entries from the text.
        "show pim neighbor", "show mrib route",
    ),
    # One `segment-routing` container holds SR-MPLS, SR-TE and SRv6 blocks,
    # and they are read, or not, apart.
    config_family_depth=("segment-routing",),
    config_families=(
        ("hostname", "identity"),
        ("interface", "physical"),
        ("lldp", "physical"),
        ("cdp", "physical"),
        ("router ospf", "ospf"),
        ("router ospfv3", "ospf"),
        ("router isis", "isis"),
        ("router bgp", "bgp"),
        ("router static", "routing"),
        ("mpls ldp", "ldp"),
        ("segment-routing", "sr"),
        # See IOS-XE: no reader of this tool reads an SR-TE policy yet.
        ("segment-routing srv6", "srv6"),
        ("segment-routing traffic-eng", ""),
        ("mpls traffic-eng", "mplste"),
        ("rsvp", "mplste"),
        # Read by teconfig.read_te_config, with the tunnel-te interfaces.
        ("explicit-path", "mplste"),
        ("vrf", "l3vpn"),
        # Read for the route targets a VRF's import and export policies set
        # and match (routepolicy.iosxr_vrf_policies).
        ("route-policy", "l3vpn"),
        ("extcommunity-set rt", "l3vpn"),
        # The sets a route-policy names, read whole (policy.iosxr_policies, G05).
        ("prefix-set", "bgp"),
        ("community-set", "bgp"),
        ("extcommunity-set", "bgp"),
        ("rd-set", "bgp"),
        ("as-path-set", "bgp"),
        ("l2vpn", "l2vpn"),
        ("evpn", "evpn"),
        ("multicast-routing", "multicast"),
        ("router pim", "multicast"),
        # G13: read by mcastconfig.read_multicast_config.
        ("router igmp", "multicast"),
        ("ptp", "ptp"),
        ("bfd", "bfd"),
        ("policy-map", "qos"),
        ("class-map", "qos"),
        ("ntp", "management"),
        ("aaa", "management"),
        ("tacacs", "management"),
        ("tacacs-server", "management"),
        ("radius", "management"),
        ("radius-server", "management"),
        ("username", "management"),
        ("line", "management"),
        ("vty-pool", "management"),
        ("ssh", "management"),
        ("telnet", "management"),
        ("http", "management"),
        ("netconf-yang", "management"),
        ("netconf", "management"),
        ("xml", "management"),
        ("grpc", "management"),
        ("snmp-server", "management"),
        ("logging", "management"),
        ("flow exporter-map", "management"),
        ("flow monitor-map", "management"),
        ("sampler-map", "management"),
        ("lpts", "management"),
        ("control-plane", "management"),
        # G17: read by management._residuals_iosxr.
        ("taskgroup", "management"),
        ("usergroup", "management"),
        ("domain", "management"),
        # G12: read by opsconfig.read_ops_config. DHCP is routing's (a relay
        # or server profile serves a VRF); probes, tracks and SPAN are
        # management's, the feature their documentation sits under.
        ("ipsla", "management"),
        ("track", "management"),
        ("dhcp ipv4", "routing"),
        ("pool vrf", "routing"),
        ("monitor-session", "management"),
        # G08: access lists and object groups, read whole by acl.read_acls.
        ("ipv4 access-list", "physical"),
        ("ipv6 access-list", "physical"),
        ("ethernet-services access-list", "physical"),
        ("object-group network", "physical"),
        # G06: HSRP and VRRP groups, read by fhrp.read_fhrp. `physical`, as the
        # interfaces they sit on: no FHRP show command is allowlisted yet.
        ("router hsrp", "physical"),
        ("router vrrp", "physical"),
        # G22: authentication key chains, read by keychain.read_key_chains.
        ("key chain", "physical"),
    ),
)


NXOS = Platform(
    key="nxos",
    label="NX-OS",
    vendor="Cisco",
    examples="Nexus 9000, 7000, 5000, 3000, Nexus 9000v",
    short="nx",
    colour_light="#7c3aed",
    colour_dark="#a78bfa",
    # NX-OS spells its interfaces in lower case and never says how fast an
    # `Ethernet` port is: `Ethernet1/49` is 1, 10, 25, 40 or 100 gigabit and
    # the name does not say, so no rate is claimed for it (see naming.py).
    abbreviations={
        "eth": "Ethernet",
        # NX-OS prints them lower-case; the canonical table spells them as
        # the other platforms do, so `Po1` and `port-channel1` are one name.
        "po": "Port-channel",
        "lo": "Loopback",
        "vl": "Vlan",
        "vlan": "Vlan",
        "mgmt": "mgmt",
        "nve": "nve",
        "tu": "Tunnel",
        "nu": "Null",
    },
    # NX-OS rejects `terminal width 0`; 511 is the widest it accepts.
    session_setup=("terminal length 0", "terminal width 511"),
    # A network-admin lands in privileged EXEC; `enable` exists and is a
    # no-op, and a second one would be sent to nothing.
    has_enable=False,
    # The prompt is `hostname#`, which every Cisco prints. The version banner
    # names the OS.
    version_markers=("cisco nexus operating system (nx-os) software",),
    ssh_banner_hints=(),
    internal_types=("mgmt",),
    management_vrfs=("management",),
    logical_types=("nve",),
    factory_hostnames=("switch",),
    builtin_names=("tacacs+", "radius", "ldap", "default", "class-default"),
    address_commands={
        # `vrf all` is what makes a VRF-aware switch list every interface.
        "ipv4": ("show ip interface vrf all",),
        "ipv6": ("show ipv6 interface vrf all",),
        "brief_ipv4": ("show ip interface brief vrf all",),
        "brief_ipv6": (),
    },
    arp_command="show ip arp detail vrf all",
    ip_mtu_command="show ip interface vrf all",
    ip_mtu_reader=_nxos_ip_mtu,
    vrf_declaration=re.compile(r"^vrf context\s+(?P<name>\S+)\s*$", re.MULTILINE),
    bgp_declaration=re.compile(r"^router bgp \d", re.MULTILINE),
    vrf_table_states_targets=False,
    vrf_table_states_interfaces=False,
    nd_command="show ipv6 neighbor detail vrf all",
    version_facts=_nxos_version,
    serial_facts=_nxos_serials,
    # The Nexus 9200 and 9300 and the Nexus 3000 switches; the 9400, 9500
    # and 7000 take line cards.
    fixed_chassis=(r"N9K-C9[23]", r"N3K-C3[0-25]"),
    fabric_markers=NXOS_FABRIC_MARKERS,
    # IS-IS is read from the columnar text on every platform; a Genie
    # failure on it is not a gap.
    text_parsed=(
        "show isis adjacency vrf all", "show isis interface vrf all",
        "show isis adjacency detail vrf all",
        "show ospfv3 neighbors vrf all", "show ospfv3 interface brief vrf all",
        "show isis database detail vrf all",
        "show ip ospf database router detail vrf all", "show ip ospf database network detail vrf all",
        # The switching readers read these from the text.
        "show spanning-tree", "show spanning-tree detail", "show interface trunk",
    ),
    config_families=(
        ("hostname", "identity"),
        ("switchname", "identity"),
        ("interface", "physical"),
        ("lldp", "physical"),
        ("cdp", "physical"),
        # `feature` lines are read for the access services they switch on;
        # the protocols they enable are documented from their own tables.
        ("feature", "management"),
        ("no feature ssh", "management"),
        ("router ospf", "ospf"),
        ("router ospfv3", "ospf"),
        ("router isis", "isis"),
        ("router bgp", "bgp"),
        ("ip route", "routing"),
        ("ipv6 route", "routing"),
        ("mpls ldp", "ldp"),
        ("segment-routing", "sr"),
        ("vrf context", "l3vpn"),
        ("ip pim", "multicast"),
        # G13: read by mcastconfig.read_multicast_config; NX-OS has no multicast
        # command group, so coverage.CONFIG_READ_FEATURES admits the key.
        ("ip msdp", "multicast"),
        ("ip igmp", "multicast"),
        ("evpn", "evpn"),
        ("nv overlay", "evpn"),
        ("vpc domain", "lag"),
        ("port-channel", "lag"),
        ("spanning-tree", "switching"),
        ("vlan", "switching"),
        ("ptp", "ptp"),
        ("bfd", "bfd"),
        ("policy-map", "qos"),
        ("copp", "management"),
        ("ntp", "management"),
        ("aaa", "management"),
        ("tacacs-server", "management"),
        ("radius-server", "management"),
        ("ip tacacs", "management"),
        ("ip radius", "management"),
        ("username", "management"),
        ("line vty", "management"),
        ("ssh", "management"),
        ("snmp-server", "management"),
        ("logging", "management"),
        ("flow exporter", "management"),
        ("flow monitor", "management"),
        ("sampler", "management"),
        ("sflow", "management"),
        ("control-plane", "management"),
        # G17: read by management._residuals_nxos, or ignored by statement.
        ("line console", "management"),
        ("vdc", "management"),
        ("cfs", "management"),
        ("rmon", "management"),
        ("cli", "management"),
        ("icam", "management"),
        ("clock", "management"),
        ("password", "management"),
        ("no password", "management"),
        ("ip domain-lookup", "management"),
        ("ip domain-name", "management"),
        ("ip name-server", "management"),
        ("system routing", "management"),
        # G12: read by opsconfig.read_ops_config; `ip dhcp snooping` is not.
        ("service dhcp", "routing"),
        ("ip dhcp relay", "routing"),
        ("ipv6 dhcp relay", "routing"),
        ("monitor session", "management"),
        # G08: access lists, read whole by acl.read_acls.
        ("ip access-list", "physical"),
        ("ipv6 access-list", "physical"),
    ),
    # Static routes from the configuration, every VRF (G10).
    static_config="ip-route-prefix",
)


JUNOS = Platform(
    key="junos",
    label="Junos",
    vendor="Juniper",
    examples="MX, ACX, PTX, EX, QFX, vMX",
    short="jn",
    colour_light="#ea580c",
    colour_dark="#fb923c",
    # Junos never abbreviates: `ge-0/0/0.0` is the whole name.
    abbreviations={},
    # Operational-mode CLI settings for this session, not configuration —
    # `set cli` is the Junos spelling of `terminal length 0`.
    session_setup=("set cli screen-length 0", "set cli screen-width 0"),
    # Login lands in operational mode with whatever the login class grants;
    # there is no `enable` to type.
    has_enable=False,
    # `admin@PE1>` — nothing Cisco prints carries an `@` before the prompt
    # character, and a Linux shell prompt has `:~$` where the `>` would be.
    # A root shell on a jump host can print `root@jump#`, which is why the
    # collector reads a prompt only from the lines after the last hop.
    prompts=(re.compile(r"(?:^|\s)[\w.-]+@[\w.-]+[>#]\s*$", re.MULTILINE),),
    # The login banner (`--- JUNOS 21.4R3.15 Kernel 64-bit`) and `show version`.
    # The third marker is what an LLDP system description says of an EX or
    # a QFX ("Juniper Networks, Inc. ex4300-48t ... kernel JUNOS 18.4R3"),
    # which names neither of the first two.
    version_markers=("--- junos ", "junos: ", "juniper networks"),
    ssh_banner_hints=(),
    # An EX or a QFX names its factory VLAN `default`.
    builtin_names=("default",),
    address_commands={
        "ipv4": ("show interfaces terse",),
        "ipv6": ("show interfaces terse",),
        "brief_ipv4": (),
        "brief_ipv6": (),
    },
    arp_command="show arp no-resolve",
    # The terse table, which the addresses come from, prints no MTU.
    ip_mtu_command="show interfaces",
    ip_mtu_reader=_junos_ip_mtu,
    ip_mtu_text=_junos_ip_mtu_text,
    version_facts=_junos_version,
    inventory_command="show chassis hardware",
    serial_facts=_junos_serials,
    serial_text=_junos_serials_text,
    # The EX2200 to EX4650 and the QFX5100 to QFX5220 switches, the QFX10002,
    # the fixed ACX routers and the MX204. A virtual chassis describes its
    # Chassis line as one, which names no model here.
    fixed_chassis=(
        r"EX[234]\d{3}", r"QFX5[12]\d\d", r"QFX10002",
        r"ACX(?:500|710|1[01]00|2[12]00|5\d{3}|7024|7100)", r"MX204",
    ),
    config_command="show configuration",
    # `bgp {` under `protocols`, in the master instance or a routing
    # instance, or the same in `display set` form.
    bgp_declaration=re.compile(r"^\s*bgp\s*\{|^set\s+(?:\S+\s+)*protocols\s+bgp\b", re.MULTILINE),
    # reth, fab and swfab are an SRX cluster's: the redundant Ethernet the
    # zones bind, and the fabric links between the two nodes.
    interface_types=(
        "ge-", "xe-", "et-", "ae", "lo", "irb", "vlan", "fxp", "em", "me",
        "gr-", "lt-", "st", "vt-", "ip-", "pp", "fti", "demux", "ps",
        "lsi", "lsq-", "mt-", "pfe-", "pfh-", "vtep", "esi", "pip",
        "reth", "fab", "swfab",
    ),
    # et- runs at anything from 25G to 400G: the name does not say, so an et-
    # link is the speed its ports report in `show interfaces` or none.
    interface_rates={"ge-": 1_000, "xe-": 10_000},
    loopback_types=("lo",),
    logical_types=(
        "lo", "irb", "vlan", "fxp", "em", "me", "gr-", "lt-", "st", "vt-", "ip-",
        "pp", "fti", "demux", "ps", "lsi", "lsq-", "mt-", "pfe-", "pfh-", "vtep",
        "esi", "pip",
    ),
    unit_zero_is_port=True,
    address_reader=_junos_addresses,
    hostname_suffixes=("-re0", "-re1"),
    # em: RE-internal and RE-to-RE; pfe/pfh: fabric; fxp/me/vme: out-of-band
    # management; bme, jsrv, cbp, pip, esi, vtep, demux: internal constructs.
    internal_types=(
        "em", "pfe-", "pfh-", "fxp", "me", "vme", "bme", "jsrv", "cbp", "pip",
        "esi", "vtep", "demux",
    ),
    # The loopback units Junos keeps for itself: lo0.16384 holds 127.0.0.1 in
    # __juniper_private2__, lo0.16385 the routing engine's own in
    # __juniper_private1__. Neither is a router identity the operator set.
    internal_names=("lo0.16384", "lo0.16385"),
    # The instance `set system management-instance` moves fxp0 into.
    management_vrfs=("mgmt_junos",),
    # Every one of these met a device whose pyATS release had no parser for
    # it, or a parser that fell over on the output: the text is the reading.
    text_parsed=(
        "show lldp neighbors", "show bgp summary", "show mpls interface",
        "show chassis hardware", "show arp no-resolve", "show route instance detail",
        "show isis adjacency", "show isis interface", "show isis adjacency detail",
        "show ospf3 neighbor", "show ospf3 interface",
        "show isis database extensive", "show ospf database router extensive",
        "show ospf database network extensive",
        "show l2circuit connections", "show l2vpn connections", "show vpls connections",
        # Configuration text: there is no parser to try.
        "show configuration policy-options",
        # The SRX tables: no parser reads either.
        "show chassis cluster status", "show security zones",
        # The switching readers read these from the text.
        "show vlans", "show ethernet-switching interface", "show ethernet-switching table",
        "show spanning-tree bridge", "show spanning-tree interface",
    ),
    config_nested=True,
    config_family_depth=("system", "protocols", "routing-options"),
    config_families=(
        ("system host-name", "identity"),
        ("interfaces", "physical"),
        ("protocols lldp", "physical"),
        ("protocols rstp", "switching"),
        ("protocols mstp", "switching"),
        ("protocols vstp", "switching"),
        ("vlans", "switching"),
        ("switch-options", "switching"),
        ("protocols ospf", "ospf"),
        ("protocols ospf3", "ospf"),
        ("protocols isis", "isis"),
        ("protocols bgp", "bgp"),
        # The master instance's AS, read for BGP's local AS (protocols._junos_router_as).
        ("routing-options autonomous-system", "bgp"),
        ("routing-options static", "routing"),
        ("routing-options rib", "routing"),
        ("protocols ldp", "ldp"),
        ("protocols mpls", "ldp"),
        ("protocols rsvp", "mplste"),
        ("protocols source-packet-routing", "sr"),
        ("routing-instances", "l3vpn"),
        # Read for the route targets a policy-built VRF states nowhere else;
        # the routing policy itself is not documented.
        ("policy-options", "l3vpn"),
        ("protocols l2circuit", "l2vpn"),
        ("protocols l2vpn", "l2vpn"),
        ("protocols vpls", "l2vpn"),
        # G07: read by l2vpnconfig (bridge domains, interface-switch connections).
        ("bridge-domains", "l2vpn"),
        ("protocols connections", "l2vpn"),
        ("protocols evpn", "evpn"),
        ("protocols pim", "multicast"),
        ("protocols igmp", "multicast"),
        ("protocols msdp", "multicast"),
        ("protocols mvpn", "multicast"),
        ("protocols ptp", "ptp"),
        ("protocols bfd", "bfd"),
        ("system ntp", "management"),
        ("system syslog", "management"),
        ("system services", "management"),
        ("system login", "management"),
        ("system tacplus-server", "management"),
        ("system radius-server", "management"),
        ("system authentication-order", "management"),
        ("system accounting", "management"),
        ("system ddos-protection", "management"),
        ("snmp", "management"),
        ("forwarding-options sampling", "management"),
        ("protocols sflow", "management"),
        ("services flow-monitoring", "management"),
        # G10: definitions read by routing.rib_groups.
        ("routing-options rib-groups", "routing"),
        # G17: read by management._residuals_junos, or ignored by statement.
        ("system archival", "management"),
        ("system name-server", "management"),
        ("system commit", "management"),
        ("system backup-router", "management"),
        ("system root-authentication", "management"),
        ("system domain-name", "management"),
        ("system domain-search", "management"),
        ("system time-zone", "management"),
        ("chassis", "management"),
        ("routing-options router-id", "management"),
        ("routing-options nonstop-routing", "management"),
        ("routing-options forwarding-table", "management"),
        ("forwarding-options hash-key", "management"),
        ("forwarding-options load-balance", "management"),
        # G08: firewall filters, read by acl.read_acls. A `policer` (no
        # fixture) is stepped over and stays unread at statement level.
        ("firewall", "physical"),
        # G33: authentication key chains, read by keychain.read_key_chains.
        # `physical`, the key G22 used for IOS `key chain`: configuration
        # only, always collected. The rest of `security` stays unclaimed.
        ("security authentication-key-chains", "physical"),
    ),
    # Static routes from the configuration, every VRF (G10).
    static_config="routing-options",
)


def _asa_version(parsed: Mapping[str, Any]) -> VersionFacts:
    """Genie's ASA parser: `asa_version`, the model, and the hostname."""
    version = parsed.get("version") if isinstance(parsed.get("version"), Mapping) else {}
    return VersionFacts(
        software=str(version.get("asa_version") or ""),
        platform=str(version.get("asa_model") or version.get("platform") or ""),
        hostname=str(version.get("hostname") or ""),
    )


def _asa_serials(version: Mapping[str, Any] | None, inventory: Mapping[str, Any] | None) -> tuple[str, ...]:
    """The chassis serial `show version` prints, and the `Chassis` row of the inventory.

    A failover pair is two chassis with two serials, and each unit also
    prints its mate's in `show failover`: the pair rule joins them there.
    Nothing here merges them, so the two units stay two nodes.
    """
    found: list[str] = []
    block = (version or {}).get("version") if isinstance(version, Mapping) else None
    if isinstance(block, Mapping):
        found.append(str(block.get("serial_number") or ""))
    for name, part in (inventory or {}).items() if isinstance(inventory, Mapping) else []:
        if isinstance(part, Mapping) and str(name).lower() == "chassis":
            found.append(str(part.get("sn") or ""))
    return _clean_serials(found)


def _asa_addresses(parsed: Mapping[str, Any], family: str) -> dict[str, list[str]]:
    """`interface -> ['10.0.12.1/24']` out of `show interface detail`.

    ASA prints the address and the mask on two lines and the parser keeps
    them apart: the address under `ipv4`, the mask as a dotted `subnet`. The
    two are joined here. Only IPv4 is in this table; the parser reads no
    IPv6 from it.
    """
    if family != "ipv4":
        return {}
    found: dict[str, list[str]] = {}
    interfaces = parsed.get("interfaces") if isinstance(parsed.get("interfaces"), Mapping) else {}
    for interface, data in interfaces.items():
        if not isinstance(data, Mapping):
            continue
        block = data.get("ipv4") if isinstance(data.get("ipv4"), Mapping) else {}
        prefix = ""
        mask = str(data.get("subnet") or "")
        if mask:
            try:
                prefix = str(ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen)
            except ValueError:
                prefix = ""
        addresses: list[str] = []
        for key, detail in block.items():
            detail = detail if isinstance(detail, Mapping) else {}
            bare = str(detail.get("ip") or str(key).split("/")[0]).strip()
            try:
                ipaddress.ip_address(bare)
            except ValueError:
                continue
            length = str(detail.get("prefix_length") or prefix)
            addresses.append(f"{bare}/{length}" if length else bare)
        if addresses:
            found[str(interface)] = sorted(set(addresses))
    return found


def _asa_aliases(parsed: Mapping[str, Any]) -> dict[str, str]:
    """`nameif -> interface`: the ARP table is keyed by the name, not the port."""
    interfaces = parsed.get("interfaces") if isinstance(parsed.get("interfaces"), Mapping) else {}
    return {
        str(data.get("name")): str(interface)
        for interface, data in interfaces.items()
        if isinstance(data, Mapping) and data.get("name")
    }


ASA = Platform(
    key="asa",
    label="ASA",
    vendor="Cisco",
    examples="ASA 5500-X, ASAv, Firepower 1000/2100/4100 running the ASA image",
    short="asa",
    colour_light="#0f766e",
    colour_dark="#2dd4bf",
    abbreviations={
        "gi": "GigabitEthernet",
        "te": "TenGigabitEthernet",
        "eth": "Ethernet",
        "et": "Ethernet",
        "po": "Port-channel",
        "ma": "Management",
        "mgmt": "Management",
        "vl": "Vlan",
        "tu": "Tunnel",
        "bvi": "BVI",
        "red": "Redundant",
    },
    # `terminal pager 0` is the ASA spelling of `terminal length 0`; there is
    # no width setting to make. Privileged mode is needed for it, and unicon's
    # ASA plugin enables before it runs the setup commands.
    session_setup=("terminal pager 0",),
    has_enable=True,
    # No prompt proves an ASA. A failover unit prints `fw1/pri/act#` and a
    # multi-context unit `fw1/admin#`, but the `host/word#` shape is not the
    # firewall's alone: a Cisco EPNM or Prime server used as a jump host logs
    # in to `jump-02/netops#`, and unicon writes the whole chain into one
    # dialog, so a router behind it was read as an ASA and its correct `os:`
    # rewritten. The first line of `show version` names the software and
    # nothing else prints it; that is what an ASA is proven by.
    prompts=(),
    version_markers=("cisco adaptive security appliance software version",),
    ssh_banner_hints=(),
    internal_types=("Management",),
    factory_hostnames=("ciscoasa",),
    builtin_names=("inside", "outside", "management", "class-default"),
    # No CDP and no LLDP on a firewall: its links are proved by ARP — keyed by
    # nameif, mapped back to the port through the interface table — and by
    # shared addressing. `show interface detail` is the one table with the
    # mask, the name and the state together.
    address_commands={
        "ipv4": ("show interface detail",),
        "ipv6": (),
        "brief_ipv4": (),
        "brief_ipv6": (),
    },
    arp_command="show arp",
    nd_command="show ipv6 neighbor",
    # No IP MTU reader: `show interface detail` prints `MTU 1500` beside the
    # MAC address, and no ASA has been checked against what it means yet.
    version_facts=_asa_version,
    serial_facts=_asa_serials,
    address_reader=_asa_addresses,
    interface_aliases=_asa_aliases,
    node_kind="firewall",
    # No parser for any of these on ASA: the text is the reading.
    text_parsed=("show route summary", "show route static", "show route connected", "show ipv6 neighbor"),
    config_families=(
        ("hostname", "identity"),
        ("interface", "physical"),
        ("route", "routing"),
        ("failover", "security"),
        ("context", "security"),
        ("admin-context", "security"),
        ("ntp", "management"),
        ("aaa", "management"),
        ("aaa-server", "management"),
        ("username", "management"),
        ("ssh", "management"),
        ("http", "management"),
        ("telnet", "management"),
        ("snmp-server", "management"),
        ("logging", "management"),
        ("flow-export", "management"),
        ("access-group", "management"),
        ("rest-api", "management"),
    ),
)


# In the order the tool offers them and the diagram stylesheet lists them.
# The order is part of the rendered output, so it is fixed here rather than
# derived from a dictionary.
PLATFORMS: tuple[Platform, ...] = (IOSXE, IOSXR, NXOS, JUNOS, ASA, IOS)

# The OS a testbed is written as when nothing says otherwise. The wizard's
# "mixed" answer resolves to it, and `disconet finalize` corrects it per device
# from what the login prompt and `show version` actually said.
DEFAULT_OS = IOSXE.key

_BY_KEY: dict[str, Platform] = {platform.key: platform for platform in PLATFORMS}


def platform_for(os_name: str | None) -> Platform | None:
    """The platform a testbed `os:` names, or None for an OS the tool does not read."""
    return _BY_KEY.get(str(os_name or "").strip().lower())


def platform_keys() -> tuple[str, ...]:
    return tuple(platform.key for platform in PLATFORMS)


def stands_in(proven: str | None, declared: str | None) -> bool:
    """Does a device proven to run `proven` collect correctly as `declared`?

    True where the proof changes nothing: the same key, or one the proven
    platform names as a stand-in. Everything else is a mismatch worth a
    second login.
    """
    if not proven or not declared:
        return False
    if str(proven).lower() == str(declared).lower():
        return True
    platform = platform_for(proven)
    return platform is not None and str(declared).lower() in platform.stands_in_for


def label_for(os_name: str | None, default: str | None = None) -> str | None:
    """What the document calls this OS. A key nobody registered is upper-cased."""
    platform = platform_for(os_name)
    if platform:
        return platform.label
    return default


def accent_for(os_name: str | None) -> str:
    platform = platform_for(os_name)
    return platform.short if platform else "unknown"


def respellings_for(os_name: str | None) -> Mapping[str, str]:
    """Another platform's full names for this OS's ports, with this OS's own (see Platform.respellings)."""
    platform = platform_for(os_name)
    return platform.respellings if platform else {}


def abbreviations_for(os_name: str | None) -> Mapping[str, str]:
    """The interface abbreviation table for an OS, or the default OS's for none."""
    platform = platform_for(os_name) or _BY_KEY[DEFAULT_OS]
    return platform.abbreviations


def detect(dialog: str) -> str:
    """The OS the login dialog proves, or "" when it proves nothing.

    Deliberately conservative: it names an OS only on evidence that cannot be
    read two ways. A wrong detection would send finalize to rewrite a correct
    testbed, which is worse than the guess it started with. A prompt beats a
    banner because a prompt is printed by the OS itself, whatever a banner
    quotes.
    """
    if not dialog:
        return ""
    for platform in PLATFORMS:
        if platform.prompt_match(dialog):
            return platform.key
    lowered = dialog.lower()
    for platform in PLATFORMS:
        for marker in platform.version_markers:
            if marker in lowered:
                return platform.key
    return ""


def hint_from_banner(banner: str) -> str:
    """An OS guess from the SSH server banner, or "" when the banner does not say."""
    lowered = (banner or "").lower()
    for platform in PLATFORMS:
        for marker in platform.ssh_banner_hints:
            if marker in lowered:
                return platform.key
    return ""
