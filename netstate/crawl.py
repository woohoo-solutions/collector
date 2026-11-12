"""The bounded crawl: switches a collected device named, visited in turn.

A neighbour protocol reports every device on the far end of every cable,
with its management address, what it is and what it runs. Today DiscoNet
talks only to the devices an operator listed. With `collect --crawl` it
also logs into the switches those devices named — and only those, because
a crawl that follows every neighbour walks across a peering link into
somebody else's network with your credentials.

**Three fences, all required.** An address is visited only if it sits in a
subnet the operator declared: the address file's subnets, kept in the
estate plan, or `--crawl-scope` on the command line. Only a neighbour
that reports the Bridge capability is visited: the routers are the
operator's to list, and a phone or a host is never logged into. A depth
and a count bound the walk. Every refusal is recorded with its reason, so
the operator sees what the crawl declined and can widen the fence on
purpose.

**The OS comes from the neighbour that named the device.** CDP carries the
software string and LLDP the system description, and the registry's
version markers read either; a device nothing identifies is refused and
recorded, never connected to with a guess.

**Nothing here sends anything.** The crawl plans; the collector connects,
with the same allowlist, the same session setup and the same credentials
as the devices in the testbed. A crawled device is written to the testbed
as a swept device is, under a placeholder that finalize renames.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from netstate.naming import hostname_key, is_chassis_id, normalise_hostname
from netstate.platforms import detect
from netstate.readers import _junos_lldp_links_from_text
from netstate.testbed import placeholder_name

DEFAULT_CRAWL_DEPTH = 2
DEFAULT_CRAWL_LIMIT = 50

# What a neighbour protocol calls a switch. CDP prints a string of words,
# LLDP a dict keyed by capability; both say bridge or switch.
_BRIDGE_WORDS = ("bridge", "mac_bridge", "switch", "b")


@dataclass
class Candidate:
    """A device a collected device named, and what it said about it."""

    name: str                      # the hostname the neighbour protocol reported
    address: str
    os: str = ""                   # the registry key the description resolved to
    via: str = ""                  # the collected device that named it
    via_interface: str = ""
    capabilities: Any = ""            # CDP's words, or LLDP's dict with `enabled` per capability
    platform: str = ""
    software: str = ""
    depth: int = 1

    @property
    def placeholder(self) -> str:
        return placeholder_name(self.address)


@dataclass
class Refusal:
    name: str
    address: str
    reason: str
    via: str = ""


@dataclass
class CrawlRecord:
    """What the crawl did, for the manifest."""

    fence: list[str]
    depth: int
    limit: int
    visited: list[dict[str, Any]] = field(default_factory=list)
    refused: list[dict[str, Any]] = field(default_factory=list)

    def decline(self, name: str, address: str, reason: str, via: str, depth: int) -> None:
        """Record a device the crawl does not visit, once however many neighbours name it.

        A device named again in a later wave keeps the refusal it was first
        given: each wave judges what its own neighbours report, and the same
        switch behind two of them is still one device declined.
        """
        device = device_key(name, address)
        if device and any(device_key(r["name"], r["address"]) == device for r in self.refused):
            return
        self.refused.append({"name": name, "address": address, "reason": reason, "via": via, "depth": depth})

    def withdraw(self, address: str) -> None:
        """A device an earlier wave declined and a later one visits was not declined after all."""
        self.refused = [r for r in self.refused if not (address and r["address"] == address)]

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "fence": list(self.fence),
            "depth": self.depth,
            "limit": self.limit,
            "visited": list(self.visited),
            "refused": list(self.refused),
        }


def parse_fence(texts: Iterable[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """The subnets a crawl may enter, from their text. Anything malformed raises."""
    fence = []
    for text in texts:
        for part in re.split(r"[,\s]+", str(text or "").strip()):
            if part:
                fence.append(ipaddress.ip_network(part, strict=False))
    return fence


def in_fence(address: str, fence: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in fence)


def bridge_capable(capabilities: Any) -> bool:
    """Does the neighbour say it switches, and has it switched on?

    CDP prints words (`Router Switch IGMP`). Genie's LLDP parsers key a
    dict by capability, and spell the bridge capability `mac_bridge` on
    IOS-XE and `bridge` on NX-OS; an entry from the `Enabled Capabilities`
    line carries `enabled: True`, and one the box only could do carries no
    `enabled` key at all, never `enabled: False`. So once the neighbour
    gave an enabled list, a bridge not on that list is switched off,
    and a router that could bridge and does not is a router.
    """
    if isinstance(capabilities, dict):
        details = [d for d in capabilities.values() if isinstance(d, dict)]
        told_enabled = any("enabled" in detail for detail in details)
        for name, detail in capabilities.items():
            word = str(name).strip().lower()
            if word not in _BRIDGE_WORDS:
                continue
            if told_enabled and not (isinstance(detail, dict) and detail.get("enabled") is True):
                continue
            return True
        return False
    words = {w.strip().lower() for w in re.split(r"[\s,/]+", str(capabilities or "")) if w.strip()}
    return any(word in _BRIDGE_WORDS for word in words)


def os_from_description(*texts: Any) -> str:
    """The registry key a software string or system description names, or ""."""
    for text in texts:
        found = detect(str(text or ""))
        if found:
            return found
    return ""


def _addresses(block: Any) -> list[str]:
    """Every address a CDP entry's address dicts or an LLDP field carry, validated."""
    out: list[str] = []
    values: list[Any] = []
    if isinstance(block, dict):
        values.extend(block.keys())
    elif isinstance(block, (list, tuple)):
        values.extend(block)
    elif block:
        values.append(block)
    for value in values:
        bare = str(value).split("/")[0].strip()
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            continue
        if bare not in out:
            out.append(bare)
    return out


def cdp_candidates(device: str, parsed: dict[str, Any], depth: int) -> list[Candidate]:
    out: list[Candidate] = []
    for entry in (parsed.get("index") or {}).values():
        if not isinstance(entry, dict):
            continue
        name = normalise_hostname(entry.get("system_name") or entry.get("device_id"))
        # IOS-XE's parser calls them entry addresses, NX-OS's interface addresses.
        addresses = (
            _addresses(entry.get("management_addresses"))
            or _addresses(entry.get("entry_addresses"))
            or _addresses(entry.get("interface_addresses"))
        )
        out.append(Candidate(
            name=name or "", address=addresses[0] if addresses else "",
            os=os_from_description(entry.get("software_version"), entry.get("platform")),
            via=device, via_interface=str(entry.get("local_interface") or ""),
            capabilities=str(entry.get("capabilities") or ""),
            platform=str(entry.get("platform") or ""), software=str(entry.get("software_version") or ""),
            depth=depth,
        ))
    return out


def lldp_candidates(device: str, parsed: dict[str, Any], depth: int) -> list[Candidate]:
    out: list[Candidate] = []
    for local, interface_data in (parsed.get("interfaces") or {}).items():
        if not isinstance(interface_data, dict):
            continue
        for port_data in (interface_data.get("port_id") or {}).values():
            if not isinstance(port_data, dict):
                continue
            for key, neighbour in (port_data.get("neighbors") or {}).items():
                neighbour = neighbour if isinstance(neighbour, dict) else {}
                name = normalise_hostname(neighbour.get("system_name") or neighbour.get("neighbor_id") or key)
                addresses = _addresses(neighbour.get("management_address")) or _addresses(
                    neighbour.get("management_address_v4")
                )
                capabilities = neighbour.get("capabilities") or {}
                out.append(Candidate(
                    name=name or "", address=addresses[0] if addresses else "",
                    os=os_from_description(neighbour.get("system_description")),
                    via=device, via_interface=str(local),
                    capabilities=capabilities if isinstance(capabilities, dict) else str(capabilities),
                    software=str(neighbour.get("system_description") or ""),
                    depth=depth,
                ))
    return out


def junos_lldp_candidates(
    device: str, parsed: dict[str, Any] | None, text: str, depth: int, known: Iterable[str] = (),
) -> list[Candidate]:
    """What a Junos box names over LLDP: the brief table, parsed or as text.

    The brief table carries the neighbour's name, its chassis ID and its
    port, never a management address or a capability. A candidate with no
    address is refused with that reason, which is the honest outcome: the
    crawl cannot follow it, and the manifest says why. `known` is the
    hostname keys the crawl already holds, which the text is read against
    as the topology reads it against the snapshot's.
    """
    out: list[Candidate] = []
    entries = _first_value(parsed, "lldp-neighbor-information") if isinstance(parsed, dict) else None
    if isinstance(entries, dict):
        entries = [entries]
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        name = normalise_hostname(entry.get("lldp-remote-system-name"))
        if not name:
            continue
        out.append(Candidate(
            name=name, address=_first_address(entry.get("lldp-remote-management-address")),
            os=os_from_description(entry.get("lldp-remote-system-description")),
            via=device, via_interface=str(entry.get("lldp-local-port-id") or entry.get("lldp-local-interface") or ""),
            capabilities=str(entry.get("lldp-remote-system-capabilities-enabled") or ""),
            software=str(entry.get("lldp-remote-system-description") or ""), depth=depth,
        ))
    if out or not text:
        return out
    # The text is read as the topology reads it, by its words: cut where the
    # header puts each column, a Port info wider than its own made one name
    # of a port and the neighbour's name, and a long port description with
    # no name after it a device called by its last words (BUG-207). A
    # neighbour that sent no name is known by its chassis id alone, which
    # the crawl has nothing to follow by.
    for link in _junos_lldp_links_from_text(device, text, known):
        if is_chassis_id(link.remote_device):
            continue
        out.append(Candidate(
            name=link.remote_device, address="", via=device, via_interface=link.local_interface, depth=depth,
        ))
    return out


def _first_address(value: Any) -> str:
    found = _addresses(value)
    return found[0] if found else ""


def _first_value(data: Any, key: str) -> Any:
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for value in data.values():
            found = _first_value(value, key)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _first_value(item, key)
            if found is not None:
                return found
    return None


def device_key(name: str, address: str) -> str:
    """One device across every neighbour that names it: its address, or its name when none was given.

    "" when the report carries neither, so nothing ties it to another report.
    """
    if address:
        return address
    key = hostname_key(name)
    return f"name {key}" if key else ""


# Why a device whose name is already taken at another address is not visited.
NAME_TAKEN = (
    "its name is already taken at another address: one device under two addresses, "
    "or two devices with one name"
)


def _fenced_out(candidate: Candidate, fence: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> str:
    """Which fence keeps a candidate out, as its refusal says it, or "" for none."""
    if not candidate.address:
        return "no management address reported"
    if not bridge_capable(candidate.capabilities):
        return "does not report the Bridge capability"
    if not in_fence(candidate.address, fence):
        return "outside the declared subnets"
    if not candidate.os:
        return "OS not identifiable from what the neighbour reported"
    return ""


def plan_wave(
    candidates: Iterable[Candidate],
    fence: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    known_addresses: set[str],
    known_names: set[str],
    room: int,
) -> tuple[list[Candidate], list[Refusal]]:
    """Which of the named devices the next wave visits, and why the rest are not.

    Judged in the order the neighbours were reported, deterministically, so
    two runs over the same estate refuse the same devices for the same
    reasons. `room` is how many more devices the count limit allows. A
    device two neighbours name is refused once, under the first report's
    reason, and not at all when a later report admits it.
    """
    chosen: list[Candidate] = []
    refused: list[Refusal] = []
    refused_devices: set[str] = set()
    seen_addresses: set[str] = set()
    seen_names: set[str] = set()

    def refuse(candidate: Candidate, label: str, reason: str) -> None:
        device = device_key(candidate.name, candidate.address)
        if device in refused_devices:
            return
        if device:
            refused_devices.add(device)
        refused.append(Refusal(label, candidate.address, reason, candidate.via))

    for candidate in candidates:
        label = candidate.name or candidate.address or "?"
        if candidate.address and candidate.address in known_addresses:
            continue   # already in the testbed, or already visited: not a refusal
        if candidate.address and candidate.address in seen_addresses:
            continue   # named by two neighbours: judged once
        reason = _fenced_out(candidate, fence)
        key = hostname_key(candidate.name) if candidate.name else ""
        if key and (key in known_names or key in seen_names):
            # A name the testbed, an earlier wave or this one already has, at
            # an address none of them has: the same device seen across another
            # link, or a second device with that name (two factory-default
            # 'Switch'). Nothing a neighbour reports tells which, so it is not
            # visited, and the record says why. One a fence keeps out anyway is
            # not recorded: most often it is a router the testbed lists, seen
            # across another link, and its name declined nothing.
            if not reason:
                refuse(candidate, label, NAME_TAKEN)
            continue
        if reason:
            refuse(candidate, label, reason)
            continue
        if len(chosen) >= room:
            refuse(candidate, label, "crawl limit reached")
            continue
        seen_addresses.add(candidate.address)
        if key:
            seen_names.add(key)
        chosen.append(candidate)
    # An earlier report that could not admit a device this wave visits
    # declined nothing.
    return chosen, [r for r in refused if r.address not in seen_addresses]


def candidates_from(
    device: str,
    state: Callable[[str, str], dict[str, Any] | None],
    cdp_command: str,
    lldp_commands: Iterable[str],
    depth: int,
    raw: Callable[[str, str], str | None] | None = None,
    known: Iterable[str] = (),
) -> list[Candidate]:
    """Every neighbour one device named, read through `state(device, command)` and the text.

    `known` is the hostname keys of the devices the crawl already holds.
    """
    out: list[Candidate] = []
    cdp = state(device, cdp_command)
    if isinstance(cdp, dict):
        out.extend(cdp_candidates(device, cdp, depth))
    lldp_commands = tuple(lldp_commands)
    for command in lldp_commands:
        lldp = state(device, command)
        if isinstance(lldp, dict) and lldp.get("interfaces"):
            out.extend(lldp_candidates(device, lldp, depth))
            return out
        if isinstance(lldp, dict) and _first_value(lldp, "lldp-neighbor-information") is not None:
            out.extend(junos_lldp_candidates(device, lldp, "", depth))
            return out
    if raw is not None and lldp_commands:
        text = raw(device, lldp_commands[-1]) or ""
        if text:
            out.extend(junos_lldp_candidates(device, None, text, depth, known))
    return out
