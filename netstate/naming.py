"""Names, and how to compare them.

Interface spellings, hostname spellings, natural sort order and the location
code a hostname carries. Every module that draws, tables or checks a name reads
it through here, so there is exactly one answer to "are these the same
interface" in the tool.

Nothing in this module reads a snapshot or writes a file; it is pure naming, so
the diagram engine and the topology builder can both depend on it without
depending on each other.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Any, Callable, Iterable

from netstate.platforms import PLATFORMS, abbreviations_for, respellings_for

# Full interface names, keyed by their lowercase form. A name that is already
# canonical is never expanded — this is what keeps IOS-XR's TenGigE from being
# rewritten into IOS-XE's TenGigabitEthernet.
_CANONICAL_INTERFACES = (
    "FastEthernet",
    "GigabitEthernet",
    "TwoGigabitEthernet",
    "FiveGigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigabitEthernet",
    "HundredGigabitEthernet",
    "TenGigE",
    "FortyGigE",
    "FiftyGigE",
    "HundredGigE",
    "TwoHundredGigE",
    "FourHundredGigE",
    "Ethernet",
    "Bundle-Ether",
    "Port-channel",
    "Loopback",
    "MgmtEth",
    "Management",
    "Serial",
    "Tunnel",
    "Tunnel-te",
    "Vlan",
    "BVI",
    # The interface an IOS-XE router (an ASR920, say) routes a bridge domain
    # through; the core adjacency is often on it rather than on the port.
    "BDI",
    "Null",
    "Multilink",
    # An ISR's WAN side: the Virtual-Access a PPP session is cloned onto,
    # the Dialer a PPPoE or LTE link is addressed on, and the modem port.
    "Virtual-Access",
    "Dialer",
    "Cellular",
    # What else an IOS-XR `show interfaces description` lists: the RP's
    # timing port, a pseudowire headend, an SR-TE policy and an IP tunnel.
    # A row whose name was not known ended the table, and the rows after
    # it were read as configuration.
    "PTP",
    "PW-Ether",
    "SR-TE",
    "tunnel-ip",
    # A Catalyst 9000's application-hosting and Bluetooth ports.
    "AppGigabitEthernet",
    "Bluetooth",
)

_CANONICAL_BY_LOWER = {name.lower(): name for name in _CANONICAL_INTERFACES}

_INTERFACE_SPLIT = re.compile(r"^([A-Za-z][A-Za-z\-]*?)\s*([0-9].*)$")

# Hostnames are read as <location...>_<what this device is>: the underscore is
# the boundary DiscoNet trusts, and the hyphen is only tried when the estate
# uses no underscore at all and every name ends in something role-shaped.
SITE_SEPARATOR = "_"

# Every example hostname in this module is written in one made-up convention,
# so that none of them is taken from a real network:
#
#     <site type>_<town><site>_<role><n>_<index>        HUB_QX4_R2_1
#
# * The site type is HUB or POP.
# * The town is two invented letters: QX, ZV or CR. CR spells a core router on
#   purpose, because a town code that reads as a role is the collision the
#   rules below have to survive.
# * The site is its number in the town, glued on (QX4, ZV17). A town with a
#   single site writes none (POP_CR), and a site may be named rather than
#   numbered, behind the town (QX_KESTREL).
# * The role is one letter and its order number (R2, C1, E1, L1), with a role
#   word in front of it or behind it where one is written (HUB_QX4_CORE_C1,
#   HUB_QX4_L1_NMS).
# * The index says which one of several it is, when there are several (_1, _2).
# * A provider edge leads with its role in place of the site type, qualified
#   or bare: U-PE_QX_KESTREL_1, PE_QX_KESTREL_2.

# A role designation and its order number, glued: R1, C2, E1, PE10. Note that
# QX4 and ZV17 match this too — a site abbreviation with a number in it looks
# exactly like a role, and no amount of staring at one name will separate them.
# Which is why the shape only ever proposes a candidate; the estate decides.
_ROLE_TOKEN = re.compile(r"^[A-Za-z]{1,3}\d{1,3}$")
# The index of a device at its location, on its own: the 1 and 2 of
# HUB_QX4_R2_1 and HUB_QX4_R2_2.
_INDEX_TOKEN = re.compile(r"^\d{1,3}$")

# Words that name what a device does rather than where it is. Estates put them
# at either end — HUB_QX4_CORE_C1 trailing, U-PE_QX_KESTREL_1 leading — and
# either way they are not a place.
#
# Every entry here is a word, spelled out. Two-letter abbreviations are
# deliberately absent even where the industry uses them: a town abbreviated
# to two letters is the single most common thing in a hostname, and any two
# letters can be one, as CR is a town before it is a core router in the
# convention above. Guessing wrong there costs a whole location; keeping
# `backbone` spelled out costs nothing, because an estate that means the word
# writes the word.
_ROLE_WORDS = frozenset(
    {
        "core", "edge", "agg", "aggr", "aggregation", "access", "dist",
        "distribution", "backbone", "gateway", "rtr", "router",
        "switch", "node", "upe", "npe", "asbr",
        # What a device is for rather than where it stands. NMS is a management
        # station, not a town, and no estate names a place after one.
        "nms", "mgmt", "oam",
    }
)
# A role qualified by a letter: U-PE is a PE facing the user, N-PE one facing
# the network. The qualifier changes which role it is, never whether it is one.
_QUALIFIED_ROLE = re.compile(r"^[A-Za-z]{1,2}-(?P<role>[A-Za-z]{1,4})$")
# A role word and, optionally, the order number behind it: CORE2, SW1. The
# number counts which one of them this is, exactly as it does in R1 and C2, and
# it does not turn the word into a place.
_ROLE_WITH_INDEX = re.compile(r"^(?P<word>[A-Za-z][A-Za-z-]*?)(?P<index>\d{1,3})?$")
# One letter with an order number behind it: R1, C2, E1, L3. This is the one
# shape reading that needs no evidence from the estate, because nobody
# abbreviates a place to a single letter — two letters can be a town, and
# QX4 and ZV17 are exactly why the two-letter case is left to the estate to
# decide.
_SINGLE_LETTER_ROLE = re.compile(r"^[A-Za-z]\d{1,3}$")

# The bare role letters an estate leads with: U-PE, U-P, PE_QX_KESTREL. They are
# read at the front of a name only, never at the back, because at the back they
# are indistinguishable from a two-letter town.
_LEADING_ROLES = frozenset({"p", "pe", "ce", "rr", "sw", "gw", "bb"})
# What an estate may write behind the place instead: the bare role letters,
# and the hardware model, `<site>_C9300_SW_1`. Either is the shape of a town
# there, so neither is read on its shape: only a position the estate fills
# with them, in most of its names, gives them up. GW stays out even there:
# behind a place it is always kept as part of the place, so a town whose code
# spells a gateway, as CR spells a core router, is never lost.
_TRAILING_ROLES = _LEADING_ROLES - {"gw"}
_MODEL_TOKEN = re.compile(r"^[A-Za-z]{1,4}\d[A-Za-z0-9-]*$")


def _is_role_word(token: str) -> bool:
    """Does this token name what a device does rather than where it stands?

    The vocabulary is matched against the word alone, so a numbered instance of
    a role reads as that role: ``CORE1`` is the first core position, the same
    way ``R1`` is the first router. A place is never in the vocabulary, so
    ``QX4`` and ``ZV17`` are unaffected — ``qx`` and ``zv`` are not words about
    what a device does.
    """
    match = _ROLE_WITH_INDEX.match(token.strip().lower())
    if not match:
        return False
    word = match.group("word")
    if word in _ROLE_WORDS:
        return True
    qualified = _QUALIFIED_ROLE.match(word)
    return bool(qualified and qualified.group("role") in _ROLE_WORDS)


def _is_leading_role(token: str) -> bool:
    """A role at the front of a name, where a two-letter abbreviation is safe.

    ``U-PE_QX_KESTREL_1`` leads with what the device is for. At the front there is
    nothing else a bare ``PE`` could be, because the location follows it; at the
    back the same two letters are far more likely to be a town.
    """
    text = token.strip().lower()
    if _is_role_word(text) or text in _LEADING_ROLES:
        return True
    qualified = _QUALIFIED_ROLE.match(text)
    return bool(qualified and qualified.group("role") in _LEADING_ROLES | _ROLE_WORDS)


def _is_device_token(token: str) -> bool:
    """Could this token be about the device rather than the place?

    True for an index (``1``), a role designation (``R2``, ``E1``) and a role
    word (``CORE``, ``PE``). It is a candidate and nothing more: ``QX4`` and
    ``ZV17`` answer true as well, and they are site abbreviations.
    """
    text = token.strip()
    return bool(
        _INDEX_TOKEN.match(text) or _ROLE_TOKEN.match(text) or _is_role_word(text)
    )


def _is_vouched_token(token: str) -> bool:
    """Could this token be about the device, if the estate says so?

    Everything :func:`_is_device_token` takes, and a bare role (``PE``,
    ``SW``) or a model (``C9300``, ``ASR920``) as well. Behind a place each is
    as likely to be a town, so one comes off only at a position the estate
    has vouched for.
    """
    text = token.strip()
    return bool(
        _is_device_token(text) or text.lower() in _TRAILING_ROLES or _MODEL_TOKEN.match(text)
    )


def normalise_interface(name: str | None, os_name: str | None = None) -> str:
    """Expand an abbreviated interface name to its full platform form.

    ``Gi0/0/0/0`` and ``GigabitEthernet0/0/0/0`` are the same interface; CDP
    and LLDP disagree about which one to report, so both are normalised before
    edges are compared. An unrecognised type is returned unchanged rather than
    guessed at.
    """
    if not name:
        return ""
    text = str(name).strip()
    match = _INTERFACE_SPLIT.match(text)
    if not match:
        return text
    prefix, rest = match.group(1), match.group(2)
    lower = prefix.lower()

    # A full name canonical on another OS that this OS spells its own way:
    # IOS XR's TenGigE, as Genie's XR parsers write it TenGigabitEthernet.
    respelled = respellings_for(os_name).get(lower)
    if respelled:
        return f"{respelled}{rest}"

    canonical = _CANONICAL_BY_LOWER.get(lower)
    if canonical:
        return f"{canonical}{rest}"

    # Junos addresses unit 0 of the port LLDP names, and unit 0 is the port:
    # `ge-0/0/0.0` and `ge-0/0/0` are one interface, spelled once. A unit
    # other than 0 is a subinterface and keeps its name, as `Gi2.100` does.
    if lower in _UNIT_ZERO_TYPES and rest.endswith(".0"):
        return f"{prefix}{rest[:-2]}"

    expanded = abbreviations_for(os_name).get(lower)
    if expanded:
        # Through the canonical table, so an OS whose abbreviations expand
        # to a lower-case spelling still lands on the one name.
        return f"{_CANONICAL_BY_LOWER.get(expanded.lower(), expanded)}{rest}"
    return text


def known_interface_names() -> tuple[str, ...]:
    """Every interface type name DiscoNet understands, longest first.

    Shared with factcheck so the document and the tripwire agree on what an
    interface name looks like. Longest first matters: `TenGigE` must be tried
    before `Te`, or the short form wins and swallows the rest.
    """
    names = set(_CANONICAL_INTERFACES)
    for platform in PLATFORMS:
        names.update(platform.abbreviations)
        names.update(platform.abbreviations.values())
        names.update(platform.interface_types)
    return tuple(sorted(names, key=lambda name: (-len(name), name)))


# The types whose first two letters another type also starts with, and the
# short form each is printed with instead: a TwentyFiveGigE cut to `Tw` is
# labelled a TwoGigabitEthernet, a FourHundredGigE cut to `Fo` a FortyGigE.
# Each reads back through the platform's abbreviations to the type it came
# from.
_SHORT_FORMS = {
    "twentyfivegige": "Twe",
    "twohundredgige": "TH",
    "fourhundredgige": "FH",
}


def abbreviate_interface(name: str) -> str:
    """Short form for diagram labels: GigabitEthernet0/0/0/0 -> Gi0/0/0/0."""
    match = _INTERFACE_SPLIT.match(name or "")
    if not match:
        return name or ""
    prefix, rest = match.group(1), match.group(2)
    if _is_fixed_type(prefix):
        return name  # already as short as it gets: ge-0/0/0
    if prefix.startswith("Bundle-Ether"):
        return f"BE{rest}"
    if prefix.startswith("Port-channel"):
        return f"Po{rest}"
    if prefix.lower().startswith("tunnel-te"):
        return f"tt{rest}"
    if prefix.lower() in _SHORT_FORMS:
        return f"{_SHORT_FORMS[prefix.lower()]}{rest}"
    return f"{prefix[:2]}{rest}"


# A type name followed by a digit, or — `irb.100`, `vlan.100` — by a unit
# alone, on the types that have no port number to put before it. IOS-XR
# numbers what sits on a route processor by the processor and its CPU,
# `MgmtEth0/RP0/CPU0/0`, so those words are taken after a slash too.
_INTERFACE_LIKE = re.compile(
    r"^(?:" + "|".join(re.escape(name) for name in sorted(
        set(_CANONICAL_INTERFACES)
        | {value for platform in PLATFORMS for value in platform.abbreviations}
        | {value for platform in PLATFORMS for value in platform.abbreviations.values()}
        | {value for platform in PLATFORMS for value in platform.interface_types},
        key=lambda name: (-len(name), name),
    )) + r")(?:\d|\.\d)(?:[\d/.:]|(?<=/)(?:RP|RSP|CPU|LC)(?=\d))*$",
    re.IGNORECASE,
)

_FIXED_TYPES = frozenset(t.lower() for platform in PLATFORMS for t in platform.interface_types)
_FIXED_RATES = {
    t.lower(): rate for platform in PLATFORMS for t, rate in platform.interface_rates.items()
}
_UNIT_ZERO_TYPES = frozenset(
    t.lower() for platform in PLATFORMS if platform.unit_zero_is_port for t in platform.interface_types
)
_LOOPBACK_TYPES = tuple(sorted({t.lower() for platform in PLATFORMS for t in platform.loopback_types}))
_INTERNAL_TYPES = tuple(sorted({t.lower() for platform in PLATFORMS for t in platform.internal_types}))
# Whole names are kept per OS: `GigabitEthernet0/0` is a Catalyst 9000's
# management port and an ISR G2's first front-panel port.
_INTERNAL_NAMES = {
    platform.key: frozenset(n.lower() for n in platform.internal_names) for platform in PLATFORMS
}
_ANY_INTERNAL_NAME = frozenset(name for names in _INTERNAL_NAMES.values() for name in names)
_MANAGEMENT_VRFS = {platform.key: frozenset(platform.management_vrfs) for platform in PLATFORMS}
_BUILTIN_NAMES = frozenset(n.lower() for platform in PLATFORMS for n in platform.builtin_names)
_FACTORY_HOSTNAMES = frozenset(n.lower() for platform in PLATFORMS for n in platform.factory_hostnames)
_HOSTNAME_SUFFIXES = tuple(sorted(
    {suffix.lower() for platform in PLATFORMS for suffix in platform.hostname_suffixes},
    key=len, reverse=True,
))
_LOGICAL_TYPES = tuple(sorted({t.lower() for platform in PLATFORMS for t in platform.logical_types}))


def _is_fixed_type(prefix: str) -> bool:
    return prefix.lower() in _FIXED_TYPES


def _starts_with_type(text: str, types: Iterable[str]) -> bool:
    """`lo0`, `irb.100`: the type, then a digit or a unit — not `Loopback0`'s `lo`."""
    lowered = text.lower()
    return any(
        lowered.startswith(t) and len(lowered) > len(t) and (lowered[len(t)].isdigit() or lowered[len(t)] == ".")
        for t in types
    )


# Short forms only ever printed with their slot: a Catalyst's `Ap1/0/1` and
# `Bl0/4`, IOS-XR's `PT0/RP0/CPU0/0`. Without one the same letters are far
# more often a host: `AP01` is an access point. An ISR's modem port is
# `Ce0/1/0`, and `CE1` is a customer edge router; only a fixed ISR's
# `Ce0` is lost, and its full name, `Cellular0`, is still read.
_SLOTTED_SHORT_FORM = re.compile(r"^(?:ap|bl|pt|ce)\d[^/]*$", re.IGNORECASE)


def is_interface_name(text: str | None) -> bool:
    """Does this string name an interface rather than something else?

    Used where a parser's key could be an interface, a neighbour or a process
    tag and only the shape tells them apart.
    """
    text = str(text or "").strip()
    return bool(_INTERFACE_LIKE.match(text)) and not _SLOTTED_SHORT_FORM.match(text)


# What each interface type runs at, in Mbit/s, where the name is all there is.
# A link's capacity is the speed its ports report in `show interfaces` first:
# a TenGigE with a 1G optic in it runs at one gigabit (see edge_capacity). A
# bundle is deliberately absent — its capacity is the sum of members DiscoNet
# did not collect, and guessing at it would put a number in the document that
# no device reported.
#
# A bare `Ethernet` is deliberately not in the table. On IOS it was a
# ten-megabit port; on NX-OS every front-panel port is `Ethernet1/n`
# whatever it runs at, and a data-centre estate drawn as ten megabit would
# be wrong in every line. A name that does not say the rate claims none.
_INTERFACE_CAPACITY = {
    "fastethernet": 100,
    "gigabitethernet": 1_000,
    "twogigabitethernet": 2_000,
    "fivegigabitethernet": 5_000,
    "tengigabitethernet": 10_000,
    "tengige": 10_000,
    "twentyfivegige": 25_000,
    "fortygigabitethernet": 40_000,
    "fortygige": 40_000,
    "fiftygige": 50_000,
    "hundredgigabitethernet": 100_000,
    "hundredgige": 100_000,
    "twohundredgige": 200_000,
    "fourhundredgige": 400_000,
}


def interface_capacity(name: str | None) -> int | None:
    """Mbit/s from the interface type, or None where the name does not say.

    This is what makes a backbone visible on a diagram: the links between the
    routers carrying the core run at a different rate from the ones hanging off
    them, and the rate is written on the interface.
    """
    match = _INTERFACE_SPLIT.match(normalise_interface(name))
    if not match:
        return None
    prefix = match.group(1).lower()
    return _INTERFACE_CAPACITY.get(prefix) or _FIXED_RATES.get(prefix)


def interface_match_key(  # noqa: D401 - see the note on canonical spellings
    name: str | None, os_name: str | None = None
) -> tuple[str, str]:
    """`(media, numbering)` — equal for two canonical spellings of one interface.

    :func:`normalise_interface` expands abbreviations, but it cannot collapse
    two names that are *both* already canonical. Genie's IOS-XR IS-IS parser
    reports `TenGigabitEthernet0/0/0/1` where CDP on the same device reports
    `TenGigE0/0/0/1`: one interface, two full names, and normalising leaves
    both exactly as they are — correctly, because each is what some device
    actually calls it.

    The rate is what they agree on, so the media half of this key is the
    capacity the interface type implies rather than its spelling. That reuses
    the one table already deciding what an interface name is worth instead of
    introducing a second one to keep in step with it.

    For comparison only. An edge keeps whichever name the device reported,
    because that is the name an operator will type.
    """
    text = normalise_interface(name, os_name)
    if not text:
        return ("", "")
    match = _INTERFACE_SPLIT.match(text)
    if not match:
        return (text.lower(), "")
    prefix, rest = match.group(1).lower(), match.group(2).strip()
    capacity = _INTERFACE_CAPACITY.get(prefix) or _FIXED_RATES.get(prefix)
    # A type with no known rate — Bundle-Ether, Loopback — keeps its own name
    # as the media half, so unrelated types can never collide on "unknown".
    return (str(capacity) if capacity else prefix, rest)


def capacity_label(mbps: int | None) -> str:
    """`10000` -> "10 Gbit/s", as a legend and a table cell want it."""
    if not mbps:
        return "capacity not known"
    if mbps >= 1_000 and mbps % 1_000 == 0:
        return f"{mbps // 1_000} Gbit/s"
    return f"{mbps} Mbit/s"


def is_loopback(name: str | None) -> bool:
    text = str(name or "")
    return text.lower().startswith("loopback") or _starts_with_type(text, _LOOPBACK_TYPES)


# The two-letter forms of a management port, as `show interfaces description`
# prints them: IOS-XE's `Ma1` and `Mg1`, IOS-XR's `Mg0/RP0/CPU0/0`, ASA's
# `Ma0/0`.
_MANAGEMENT_SHORT_FORMS = ("ma", "mg")


def is_physical(name: str | None) -> bool:
    """Is this a real port rather than a logical construct?

    The infrastructure addressing table is about cabling, so loopbacks,
    tunnels, BVIs, null interfaces, IOS-XR's pseudowire headends and SR-TE
    policies are not it, nor a Virtual-Access or a Dialer, which a PPP
    session or a dial profile stands up over a port, nor the
    Virtual-Template a Virtual-Access is cloned from. A bundle is: it
    terminates cables and carries the adjacency the table exists to
    describe, and a Multilink is the bundle of a router's serial lines.

    Nor is a type some platform keeps out-of-band or internal: NX-OS's
    `mgmt0` and Junos's `vme0` are cabled to a management switch, not to
    the network, and a down one with an address on it is not a link. The
    short forms say the same: `Mg` and `Ma` are a management port on every
    platform that prints them, so `Mg0/RP0/CPU0/0` is what
    `MgmtEth0/RP0/CPU0/0` is.
    """
    text = str(name or "")
    if not text:
        return False
    logical = (
        "loopback", "tunnel", "null", "vlan", "bvi", "mgmteth", "management", "pw-ether", "sr-te",
        "virtual-access", "virtual-template", "dialer",
    )
    return not text.lower().startswith(logical) and not _starts_with_type(
        text, _LOGICAL_TYPES + _INTERNAL_TYPES + _MANAGEMENT_SHORT_FORMS
    )


# Tunnels and the sessions a dial or PPP profile stands up: GRE, DMVPN and
# IPsec `Tunnel`s (and IOS-XR's `tunnel-te`/`tunnel-ip`), a `Dialer`, a
# `Virtual-Access` and the `Virtual-Template` it is cloned from, and Junos's
# GRE (`gr-`), IP-IP (`ip-`), logical (`lt-`), secure (`st0`), flexible
# (`fti`) and PPPoE (`pp0`) tunnels. `Tu` is the one short form a neighbour
# or an adjacency table prints for any of them.
_TUNNEL_NAMES = ("tunnel", "dialer", "virtual-access", "virtual-template")
_TUNNEL_TYPES = ("tu", "gr-", "ip-", "lt-", "st", "fti", "pp")


def is_tunnel(name: str | None) -> bool:
    """Does this interface ride other ports rather than terminate a cable?

    An adjacency over a tunnel is real, and the routing chapters and the
    failure analysis read it, but nothing is cabled to a tunnel: the far end
    is wherever the underlay delivers it, often across a provider's network.
    The physical figure draws cables, so a tunnel is no line in it, and no
    neighbour protocol was ever going to report a cable under one.
    """
    text = str(name or "")
    return text.lower().startswith(_TUNNEL_NAMES) or _starts_with_type(text, _TUNNEL_TYPES)


def is_internal(name: str | None, os_name: str | None = None, vrf: str | None = None) -> bool:
    """An interface whose addresses are never evidence of a link.

    Fabric, RE-to-RE and out-of-band management interfaces carry private
    addresses repeated on every box and shared over a switch the document is
    not about; an ARP entry or a subnet on one of them draws a link that does
    not exist. They stay in the addressing tables, where they are facts.

    A whole name is read on the device's own OS, and without one a name that
    is out-of-band on any platform is. An interface in the VRF its OS keeps
    for the management port is out-of-band whatever it is called.
    """
    text = str(name or "")
    key = str(os_name or "").strip().lower()
    if is_platform_management_vrf(vrf, os_name):
        return True
    if normalise_interface(text, os_name).lower() in _INTERNAL_NAMES.get(key, _ANY_INTERNAL_NAME):
        return True
    return _starts_with_type(text, _INTERNAL_TYPES)


def is_platform_management_vrf(vrf: str | None, os_name: str | None) -> bool:
    """The VRF the OS itself creates for its management port (`Mgmt-intf`, NX-OS `management`).

    Read on the device's own OS: a VRF the operator named alike elsewhere is theirs.
    """
    return bool(vrf) and vrf in _MANAGEMENT_VRFS.get(str(os_name or "").strip().lower(), ())


def is_builtin_name(name: str | None) -> bool:
    """Whether a name a configuration used is a platform's own word (`tacacs+`, `inside`)."""
    return str(name or "").strip().lower() in _BUILTIN_NAMES


def is_junos_instance_of_its_own(name: str | None) -> bool:
    """Whether a routing instance is one Junos keeps for itself (`__juniper_private1__`, `__master.anon__`).

    Junos names its own instances between double underscores; their tables
    (`__juniper_private1__.inet.0`) carry the routes between the routing
    engine and the line cards, are no table the operator built and name
    nobody. Only that shape: a VRF the operator called `_ACME` is theirs.
    """
    text = str(name or "").strip()
    return len(text) > 4 and text.startswith("__") and text.endswith("__")


def is_factory_hostname(name: str | None) -> bool:
    """Whether a hostname is one a platform ships with (`Router`, `Switch`), which names nobody."""
    return str(name or "").strip().lower() in _FACTORY_HOSTNAMES


def hostname_key(name: str | None) -> str:
    """The form two spellings of one device's name agree on.

    Lower case, no domain, no CDP serial suffix, and no routing-engine suffix:
    a dual-RE Junos box logs in as `X-re0` and is `X` to IS-IS and LDP, and a
    topology that keeps them apart draws every core link twice.
    """
    text = normalise_hostname(name).lower()
    for suffix in _HOSTNAME_SUFFIXES:
        if text.endswith(suffix) and len(text) > len(suffix):
            return text[: -len(suffix)]
    return text


def _full_name(name: str | None) -> str:
    """A whole name, domain and all, in the one case: what `SW1.AMS.example.net` and `sw1.ams.example.net` share.

    A CDP serial suffix goes, as :func:`normalise_hostname` drops it, since
    it is not part of the name.
    """
    return re.sub(r"\s*\([^)]*\)\s*$", "", str(name or "").strip()).lower()


class NameIndex(dict):
    """`hostname_key -> device name`, and each device's whole name besides.

    A dict by the short key, which is what every reader looks a peer up by;
    :meth:`match` tries the whole name first, which is what tells two
    testbed entries that share a short name apart.
    """

    def __init__(self) -> None:
        super().__init__()
        self.full: dict[str, str] = {}

    def match(self, reported: str | None) -> str:
        """The device a reported name means, or "" where none does or two could."""
        text = str(reported or "").strip()
        return self.full.get(_full_name(text)) or self.get(hostname_key(text), "")


def device_name_index(
    names: Iterable[str], learned: Iterable[tuple[str, str]] = ()
) -> NameIndex:
    """`hostname_key -> device name` for every name a peer may report a device by.

    A neighbour reports a device by the hostname the device gave it, and the
    testbed may call that device something else: `collect --finalize` keeps
    the operator's name, and a hand-written testbed names boxes as the
    operator likes. Matched against testbed names alone, `CORE-R1` from a
    neighbour's CDP table, an IS-IS hostname TLV or a BGP description is a
    second device beside the testbed's `core1`.

    ``names`` are the devices' own names, in the order they are documented;
    ``learned`` is `(device name, hostname it gave)` for each collected
    chassis. The names come first, so a testbed name always means its own
    entry, even where another device misconfigured with that hostname. A
    learned hostname follows; one that two separate devices both give names
    neither, because the report could mean either and choosing one would be
    a guess, and a factory hostname (`Switch`, `Router`) names nobody at all.

    Two names can share a short key too: `sw1.ams.example.net` and
    `sw1.lon.example.net` are both `sw1`, and so are `SW1` and `sw1`. The
    first used to take the key, and every report of the second — its own
    included — was drawn on the first. A short key two names share names
    neither, by the same rule, and no hostname either device gave claims it;
    each name still matches itself whole (see :meth:`NameIndex.match`), so a
    neighbour that reports `sw1.lon.example.net` means London.

    The topology's cabling and every protocol reading resolve names through
    this one index, so a device is the same device in Figure 1, in the
    protocol figures and in the link-state database.
    """
    index = NameIndex()
    owners: dict[str, list[str]] = {}
    spellings: dict[str, set[str]] = {}
    for name in names:
        key = hostname_key(name)
        if key:
            owners.setdefault(key, []).append(name)
        spellings.setdefault(_full_name(name), set()).add(name)
    for key, owned in owners.items():
        if len(set(owned)) == 1:
            index[key] = owned[0]
    for full, owned in spellings.items():
        if full and len(owned) == 1:
            index.full[full] = next(iter(owned))
    givers: dict[str, set[str]] = {}
    for name, hostname in learned:
        key = hostname_key(hostname)
        # A factory hostname is no hostname (D-11): every switch nobody named
        # is `Switch`, and a neighbour's `Switch` means none of them in
        # particular, however many of them were collected.
        if key and not is_factory_hostname(key):
            givers.setdefault(key, set()).add(name)
    for key, devices in givers.items():
        if len(devices) == 1 and key not in owners:
            index[key] = next(iter(devices))
    return index


# What a neighbour reports where it has no name to give, dots and all: an
# IS-IS system ID (with its selector and fragment, where printed), which is
# also the shape of a dotted MAC that LLDP gives as a chassis ID, and an IPv4
# address.
_SYSTEM_ID = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}(?:\.[0-9a-f]{2}(?:-[0-9a-f]{2})?)?$", re.IGNORECASE)
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_system_id(text: str | None) -> bool:
    """An IS-IS system ID, `1921.6800.1011`, or a MAC in the same dotted form."""
    return bool(_SYSTEM_ID.match(str(text or "").strip()))


_COLON_MAC = re.compile(r"^[0-9a-f]{2}(?P<sep>[:-])[0-9a-f]{2}(?:(?P=sep)[0-9a-f]{2}){4}$", re.IGNORECASE)


def is_chassis_id(text: str | None) -> bool:
    """A neighbour's chassis id where its name should be: a MAC in any spelling, or an address.

    LLDP gives the chassis id in place of a System Name the far end never
    sent, which is what a phone, a server or an access point does. Read as a
    hostname, every one of them was a device of its own, counted, tabled and
    drawn as a box labelled with a MAC that tells the reader nothing.
    """
    text = str(text or "").strip()
    if is_system_id(text) or _COLON_MAC.match(text):
        return True
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def normalise_hostname(name: str | None) -> str:
    """Strip the domain and any CDP serial-number suffix from a hostname.

    ``R2.lab.example.net`` and ``R2(FTX1234A1B)`` are both ``R2``. A system
    ID, a MAC or an address keeps every group: cut at the first dot like a
    domain, `1921.6800.1011` and `1921.6800.1012` were both `1921`, one
    device that does not exist standing for two that do.
    """
    if not name:
        return ""
    text = str(name).strip()
    text = re.sub(r"\s*\([^)]*\)\s*$", "", text)
    if is_system_id(text) or _IPV4.match(text):
        return text
    return text.split(".")[0].strip()


def _separator_for(names: tuple[str, ...]) -> str:
    """Which character this estate uses between the parts of a hostname.

    The underscore is taken as a boundary wherever it appears. The hyphen is
    not, because it is common inside ordinary hostnames — ``core-rtr-01`` is
    one name for one device, not a location and a role. It is only read when
    the estate contains no underscore anywhere *and* every multi-part name ends
    in a role designation, which is the estate saying it is spelled that way.
    """
    if any(SITE_SEPARATOR in name for name in names):
        return SITE_SEPARATOR
    hyphenated = [name for name in names if "-" in name]
    if len(hyphenated) < 2:
        return SITE_SEPARATOR
    if all(_ROLE_TOKEN.match(name.split("-")[-1]) for name in hyphenated):
        return "-"
    return SITE_SEPARATOR


def _tokens(name: str, separator: str) -> list[str]:
    """One hostname split into its parts, or [] if it carries no boundary."""
    tokens = name.split(separator)
    if len(tokens) < 2 or any(not token.strip() for token in tokens):
        # No boundary, or a name that begins or ends with one: nothing here
        # says where the device is, and a guess is worse than a blank cell.
        return []
    return [token.strip() for token in tokens]


def _per_device_position(
    paths: Iterable[list[str]], candidate: Callable[[str], bool] = _is_device_token, strict: bool = False
) -> bool:
    """Is the last token of these paths about the device rather than the place?

    Two readings have to be told apart and they are identical in any one name:
    ``R2`` in ``HUB_QX4_R2`` says which router, ``QX4`` in ``HUB_QX4`` says
    which town, and both are letters with a number behind them. What separates
    them is not the token — it is how the estate uses the position.

    A device position holds a **shared vocabulary**: a handful of designations,
    ``R2``, ``C2``, ``E1``, reused across the whole estate. So it has two
    properties, and both are required here:

    * **Fewer words than places to say them.** The distinct values at the
      position number fewer than the prefixes carrying them. A town position
      is the reverse — many towns under a few site types.
    * **Most names take part.** At least half the names at the position end in
      a value that some other prefix uses too.

    The second test alone was the earlier reading, and it was wrong in a way
    any estate of more than a few sites shows at once: one town code that
    happens to appear under two site types — ``HUB_QX4`` beside ``POP_QX4`` —
    made every town look like a role, and every location collapsed into its
    site type, ``HUB`` or ``POP``. A coincidence is not a vocabulary. The first
    test is what tells them apart.

    ``strict`` counts every name at the position in the second test, not
    only the names that end in a `candidate`: a token that could as well be
    a town has to end most of the estate's names before it is a role.
    """
    tails: list[tuple[str, tuple[str, ...]]] = []
    names = 0
    for path in paths:
        if len(path) < 2:
            continue
        names += 1
        if not candidate(path[-1]):
            continue
        tails.append((path[-1].lower(), tuple(token.lower() for token in path[:-1])))
    if not tails:
        return False

    prefixes: dict[str, set[tuple[str, ...]]] = {}
    for value, prefix in tails:
        prefixes.setdefault(value, set()).add(prefix)
    if len(prefixes) >= len({prefix for _, prefix in tails}):
        return False

    shared = {value for value, seen in prefixes.items() if len(seen) > 1}
    covered = sum(1 for value, _ in tails if value in shared)
    return covered * 2 >= (names if strict else len(tails))


def _strip_per_device_tail(
    paths: dict[str, list[str]], governing: list[str]
) -> dict[str, list[str]]:
    """Take the device off the end of every name, position by position.

    Reading right to left, and stopping at the first position the estate does
    not vouch for: an estate whose names end `<role><n>_<index>` loses two
    tokens, one whose names end in a place loses none. The estate vouches for
    a position either through its role designations and indexes, or through
    bare roles and models ending most of its names; once it has, a bare role
    or a model there comes off too, so the C9300 goes with the ASR920 beside
    it.
    """
    working = {name: list(path) for name, path in paths.items()}
    while True:
        evidence = [working[name] for name in governing if name in working]
        if not (
            _per_device_position(evidence)
            or _per_device_position(evidence, _is_vouched_token, strict=True)
        ):
            return working
        working = {
            name: (path[:-1] if len(path) > 1 and _is_vouched_token(path[-1]) else path)
            for name, path in working.items()
        }


def _strip_by_shape(tokens: list[str]) -> list[str]:
    """The fallback for an estate too small to have a convention to read.

    One name says nothing about which of its parts repeat, so the shape is all
    there is: an index and a role designation come off the end. It is the
    weaker reading — it cannot tell ``QX4`` from ``E1`` — and it only runs
    where the estate offered no evidence at all. So it takes one of each and
    no more: a name has one role and one index, and a second token of the
    same shape in front of them is the town, as ``QX4`` is in ``HUB_QX4_R2``.
    """
    tokens = list(tokens)
    if len(tokens) > 1 and _INDEX_TOKEN.match(tokens[-1]):
        tokens.pop()
    if len(tokens) > 1 and _ROLE_TOKEN.match(tokens[-1]):
        tokens.pop()
    while len(tokens) > 1 and _is_role_word(tokens[-1]):
        tokens.pop()
    return tokens


def _strip_trailing_role(tokens: list[str]) -> list[str]:
    """A trailing word from the role vocabulary is never the place.

    ``HUB_QX4_CORE`` and ``HUB_QX4_EDGE`` are one building. This needs no
    evidence from the estate — the vocabulary is the evidence — and it runs
    whether or not the statistical reading found anything, because a role word
    can sit behind a place position that rightly stayed put.

    A single letter with a number behind it comes off here too.
    `HUB_QX4_L1_NMS` is a management station at HUB_QX4, and once `NMS` has
    gone the `L1` in front of it is the same kind of token as the `R1` in
    `HUB_QX4_R1`. Two letters are left alone, because the `CR` of `POP_CR` is
    a town.
    """
    tokens = list(tokens)
    while len(tokens) > 1 and (
        _is_role_word(tokens[-1]) or _SINGLE_LETTER_ROLE.match(tokens[-1].strip())
    ):
        tokens.pop()
    return tokens


def _strip_leading_role(tokens: list[str]) -> list[str]:
    """Take a role off the front: U-PE_QX_KESTREL_1 is at QX_KESTREL.

    Some estates lead with what the device is rather than where it is, and then
    the U-PE and the U-P at one location have to land in the same place. Only
    the role vocabulary is read here — a site type such as HUB or POP leads just
    as often and is part of the location. A bare two-letter role is accepted at
    the front and nowhere else: ahead of the location there is nothing else a
    `PE` could be, while behind it the same two letters are far more likely to
    be a town.
    """
    tokens = list(tokens)
    while len(tokens) > 1 and _is_leading_role(tokens[0]):
        tokens.pop(0)
    return tokens


@lru_cache(maxsize=64)
def _codes(names: tuple[str, ...], convention: tuple[str, ...]) -> dict[str, str]:
    separator = _separator_for(convention)
    tokens = {name: _tokens(name, separator) for name in names}
    sited = {name: path for name, path in tokens.items() if path}
    # The convention is read from the devices the estate is made of, and then
    # applied to every name. A neighbour protocol hears far more than the
    # testbed contains, and an IP phone's name is not evidence about how the
    # network is named.
    governing = [name for name in convention if name in sited] or list(sited)

    stripped = _strip_per_device_tail(sited, governing)
    if all(stripped[name] == sited[name] for name in sited):
        # The estate said nothing — one device, or one location, or names that
        # end in a place. Fall back to reading each name on its own.
        stripped = {name: _strip_by_shape(path) for name, path in sited.items()}
    sited = {
        name: _strip_trailing_role(_strip_leading_role(path))
        for name, path in stripped.items()
    }
    governing_paths = {name: sited[name] for name in governing}

    # A token every name ends with is not what distinguishes one location from
    # another — a whole estate in one LAB says nothing by repeating it — so it
    # comes off, as long as no two locations collapse into one by losing it.
    # Repeated, because an estate can carry more than one such word. There has
    # to be something to distinguish first: with one location in the estate,
    # every token is common to all of it, and dropping them would shorten the
    # site's name for no reason.
    while (
        len({tuple(path) for path in governing_paths.values()}) > 1
        and all(len(path) > 1 for path in governing_paths.values())
    ):
        tails = {path[-1].lower() for path in governing_paths.values()}
        if len(tails) > 1:
            break
        shortened = {name: path[:-1] for name, path in governing_paths.items()}
        if len({tuple(path) for path in shortened.values()}) != len(
            {tuple(path) for path in governing_paths.values()}
        ):
            break
        governing_paths = shortened
        # The same word comes off every other name that ends in it, so one
        # estate never carries two spellings of the same location.
        sited = {
            name: (path[:-1] if len(path) > 1 and path[-1].lower() in tails else path)
            for name, path in sited.items()
        }

    return {
        name: (separator.join(sited[name]) if name in sited else "")
        for name in names
    }


def location_codes(
    hostnames: Iterable[str], convention: Iterable[str] | None = None
) -> dict[str, str]:
    """`hostname -> location code`, decided across the whole estate.

    A hostname carries three things: where the device is, what it is, and which
    one of those it is at that location. Only the first belongs in the Location
    column and on the box the diagram draws around a site, and the three cannot
    be told apart from one name in isolation — ``HUB_QX4_R1`` and ``POP_CR_C2``
    are only legible beside each other.

    So the whole estate is read at once. The role designation and its order
    number come off the end (``R1``, ``C2``, ``E1``), then any trailing word
    that names a role rather than a place, then any word every name repeats.
    What is left is the location, in full: where an estate prefixes a site type
    to a site name — ``HUB_QX4``, ``HUB_ZV17``, ``POP_CR`` — the type alone is not
    a location, and keeping both is what distinguishes the sites from one
    another.

    Where a name carries no boundary at all the answer is the empty string, and
    every table leaves the Location cell blank for an engineer to fill in
    rather than guessing at a building.

    `convention` narrows which names the reading is *derived* from, while every
    name still gets a code. A neighbour protocol on a real estate reports
    hundreds of devices nobody pointed the tool at — phones, access points,
    somebody else's switches — and their names are not evidence about how this
    network is named. Pass the collected devices and the convention is theirs.
    """
    names = tuple(sorted({str(name) for name in hostnames if str(name).strip()}))
    governing = (
        tuple(sorted({str(name) for name in convention if str(name).strip()}))
        if convention is not None
        else names
    )
    return dict(_codes(names, governing or names))


def site_of(hostname: str | None) -> str:
    """The location code of one hostname, read without the rest of the estate.

    The estate-wide reading is the accurate one — see :func:`location_codes` —
    and every table and diagram uses it through the topology, which records the
    code it derived against each node. This is the fallback for a name that
    reaches a diagram without one, and it answers for that name alone.
    """
    name = str(hostname or "").strip()
    if not name:
        return ""
    return location_codes([name]).get(name, "")


def natural_key(name: str) -> tuple:
    """Sort R2 before R10, deterministically.

    Each run is tagged with its own kind before its value, so a key never
    compares a number against a word. Diagrams mix hostnames with the raw
    identifiers of peers that resolved to nothing — ``R2`` beside
    ``10.0.0.4:0`` — and a key that raises on that pair would take a whole
    diagram down over one uncollected neighbour.

    The runs alone read R01 as R1 and r1 as R1, and two names that compare
    equal have no order between them: a cable joining them would be oriented
    by whichever end reported it, and drawn twice. The name as spelled settles
    that tie, and only that, so R2 still sorts before R10.
    """
    runs = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part.lower())
        for part in re.split(r"(\d+)", str(name))
        if part != ""
    )
    return runs, str(name)


def site_groups(nodes: Iterable[Any]) -> dict[str, list[str]]:
    """`site -> hostnames`, in drawing order, or {} when there is no grouping.

    Accepts node dictionaries carrying `hostname`, or bare hostnames. A node
    that already carries a `site` keeps it — the topology derived it against
    the whole estate, which is the reading to trust — and anything else is read
    here, again across every name given at once.

    Devices whose names carry no location code are collected under "" so they
    are still placed; the diagram draws no boundary around that bucket. Fewer
    than two real sites means the names are not site-coded at all, and the
    ordinary ring layout is left alone.
    """
    entries = [
        (node["hostname"], node.get("site")) if isinstance(node, dict) else (str(node), None)
        for node in nodes
    ]
    codes = location_codes(hostname for hostname, site in entries if site is None)
    groups: dict[str, list[str]] = {}
    for hostname, site in entries:
        code = site if site is not None else codes.get(hostname, "")
        groups.setdefault(code, []).append(hostname)
    if len([site for site in groups if site]) < 2:
        return {}
    return {
        site: sorted(groups[site], key=natural_key)
        # "" sorts first among real codes, so it is moved to the end explicitly.
        for site in sorted(groups, key=lambda s: (s == "", natural_key(s)))
    }
