"""Read-only state collection from network devices via pyATS/Genie.

Collection strategy, per allowlisted command:

1. ``device.execute(<command>)`` captures the raw output, which is redacted and
   written to ``raw/`` before anything else happens to it.
2. ``device.parse(<command>, output=...)`` parses the output already captured,
   so each command is executed exactly once and the raw file and the structured
   state are guaranteed to describe the same sample. The `show version` that
   identifies a device behind a bare prompt is that sample; only a device
   identified before its second enable, on a session not yet privileged, is
   asked it again once privileged.
3. Commands with no Genie parser keep their raw text only and are flagged
   ``unparsed`` in the manifest. ``show running-config`` is never parsed: it is
   listed as ``raw_only`` and feeds Appendix B configuration excerpts.

Every command that reaches a device passes through :class:`CommandPolicy`,
which is loaded from ``commands.yaml``. A command that is not in the allowlist
raises :class:`CommandNotAllowed`. This follows the mig-copilot collector.
"""

from __future__ import annotations

import contextlib
import functools
import glob
import ipaddress
import hashlib
import json
import logging
import os
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml

from netstate.inheritance import effective_lines
from netstate.ledger import ConfigLine, numbered_lines

from netstate import __version__
from netstate import private
from netstate import store
from netstate import platforms
from netstate import hostkeys
from netstate import legacyssh
from netstate.crawl import (
    DEFAULT_CRAWL_DEPTH, DEFAULT_CRAWL_LIMIT, Candidate, CrawlRecord, candidates_from, parse_fence,
    plan_wave,
)
from netstate.naming import hostname_key, is_interface_name, normalise_interface
from netstate.probe import TELNET, TELNET_PORT, probe_address
from netstate.readers import _hostname_from, device_serials, device_version
from netstate.testbed import ENV_USERNAME, credential_sets, disabled_devices

log = logging.getLogger(__name__)

DEFAULT_COMMANDS_FILE = Path(__file__).with_name("commands.yaml")

# Exec-mode terminal settings applied once per connection so that output is not
# paginated. They are session-local, alter no configuration, and come from
# `Platform.session_setup` in platforms.py — a module constant per OS that no
# testbed value can reach. unicon's own default init sequence is explicitly
# overridden because it would otherwise send `no logging console`, which is a
# CONFIG command.
SESSION_CONFIG_SETUP: list[str] = []  # must stay empty — read-only tool

# Both lists are passed to `connect()` as explicit keywords, which beat the
# testbed's `connections.<name>.arguments:` block. Anything a testbed sets
# under those two keys is therefore dropped, and dropped silently unless
# something says so — see _warn_about_overridden_arguments.
OVERRIDDEN_CONNECTION_ARGUMENTS = ("init_exec_commands", "init_config_commands")

# What unicon's IOS-XE plugin would otherwise send during every connect, on
# its own and outside the allowlist: `show version | include operating mode`,
# then on a controller-managed (SD-WAN) device `pnpa service discovery stop`,
# which is not a read, and token discovery (`show version`, `show inventory`,
# `uname -a`); and `show install summary` to learn the software version. An
# operating_mode tells the plugin the first question is answered — True is
# what it stores itself once it has asked — and learn_os_version off stops the
# second. Checked against unicon 26.8's own mock devices: an IOS-XE connect
# then types the login and `enable` and nothing else, and no other platform's
# plugin sends or changes anything either way. Nothing is lost: the version
# comes from the allowlist's `show version`, and no Genie parser is chosen by
# the version unicon would have learned.
# Re-checked on unicon 26.10, the pinned release, against its mock IOS-XE
# device by disconet/tests/test_dependency_pins.py on every suite run.
QUIET_CONNECT_ARGUMENTS: dict[str, Any] = {"operating_mode": True, "learn_os_version": False}

# The distributions a run's commands go through on their way to the snapshot:
# unicon opens and drives the session (the quiet connect above rests on its
# plugin internals) and Genie's parsers turn the output into what the
# documents read. Each run records the release of each in its manifest, so a
# snapshot can be re-read with the stack that wrote it. pyproject.toml bounds
# them to the line this was checked against, and constraints/ pins it exactly.
PYATS_DISTRIBUTIONS = ("pyats", "genie", "genie.libs.parser", "unicon", "unicon.plugins")


def pyats_versions() -> dict[str, str | None]:
    """The installed release of each of PYATS_DISTRIBUTIONS, None for one that is not installed.

    Read from the installed package metadata, never by importing: a run that
    never reached a device still records what it would have used, and a
    machine without pyATS (the offline suite on Windows) records None rather
    than failing.
    """
    from importlib import metadata

    versions: dict[str, str | None] = {}
    for name in PYATS_DISTRIBUTIONS:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    return versions

# Some IOS-XE deployments authenticate a session all the way to `hostname#`
# and still leave it unprivileged: the session has to send `enable` a second
# time and answer the password prompt before the device will accept anything,
# `terminal length 0` included. Devices that behave this way are declared in
# the testbed with `custom: {double_enable: true}`.
#
# This is a privilege transition, not a configuration change. The command is a
# module constant rather than anything the testbed can influence, so the only
# string this can ever send is the literal `enable`.
SECOND_ENABLE_COMMAND = "enable"
ENABLE_PASSWORD_PROMPT = r"^.*[Pp]assword:\s*$"
DOUBLE_ENABLE_KEY = "double_enable"

# unicon defaults are CONNECTION_TIMEOUT=60 and EXEC_TIMEOUT=60. Virtual
# routers (CSR1000v, XRv) are markedly slower than real hardware, and a large
# `show running-config` can outrun 60s, so the command default is raised.
# Both are overridable per run — a real hang should still surface, not stall.
DEFAULT_CONNECT_TIMEOUT = 90
DEFAULT_COMMAND_TIMEOUT = 120
DEFAULT_WORKERS = 5

# A virtual router occasionally loses its first answer to a burst of console
# logging while the session is still settling. One retry of the same
# allowlisted show command recovers it without weakening anything.
TIMEOUT_ATTEMPTS = 2
RETRY_PAUSE = 2.0
# What a command left unsent reads as, once a timed-out answer could not be
# cleared by a fresh session. It is a gap, never a guess at what it would say.
NOT_SENT_DETAIL = "not sent: a command timed out and the session could not be reopened"
# What a planned command reads as when a defect stopped the device's
# collection before its answer was kept: the gap list names it, rather than
# naming only what came back badly as if the rest had been asked.
NOT_SENT_AFTER_ERROR_DETAIL = "not collected: the device's collection stopped on an unexpected error"

# Defence in depth: even if commands.yaml is edited badly, these never ship.
CONFIG_TOKENS = frozenset(
    {
        "configure",
        "config",
        "conf",
        "write",
        "wr",
        "copy",
        "erase",
        "delete",
        "reload",
        "clear",
        "commit",
        "rollback",
        "shutdown",
        "no",
        "set",
        "request",
        "install",
        "reset",
        "restart",
        "format",
        "archive",
        "test",
        "debug",
        "undebug",
        "monitor",
        "tclsh",
        "guestshell",
        "license",
    }
)


# The optional collection groups, in menu order. Every one of them is a real
# allowlist entry in commands.yaml; selecting a subset narrows what leaves the
# tool and can never widen it. Protocols and services are offered as two
# separate menus because they answer two different questions — how the network
# is wired together, and what it carries.
# `multicast` is one key covering both the global table and multicast VPN,
# because that is one question. A core that carries a customer's multicast
# carries it over the same links its own PIM adjacencies are formed on, and a
# document that described one without the other would explain half a path.
# `switching` sits with the protocols beside `lag` for the same reason: it is
# how the estate is wired below the routers, not a service it carries.
PROTOCOL_FEATURES = ("ospf", "isis", "lsdb", "bgp", "vpnv4", "routing", "ldp", "bfd", "sr", "srv6", "multicast", "ptp", "lag", "switching")
SERVICE_FEATURES = ("l3vpn", "l2vpn", "evpn", "mplste", "srte", "qos", "security")
# The management plane is neither a protocol the network is wired with nor a
# service it carries: it is how the devices are kept in time, reached, logged
# and protected. One key, its own menu, its own chapter.
MANAGEMENT_FEATURES = ("management",)
ALL_FEATURES = PROTOCOL_FEATURES + SERVICE_FEATURES + MANAGEMENT_FEATURES

# How much a link has to prove before the topology counts it. This changes no
# command and reaches no device — it is a reading of evidence already on disk,
# which is why a snapshot taken one way rebuilds the other way unchanged.
DISCOVERY_MODES = ("loose", "strict")
DEFAULT_DISCOVERY_MODE = "loose"

FEATURE_LABELS = {
    "ospf": "OSPF",
    "isis": "IS-IS",
    # The link-state databases themselves, a separate selection from the
    # adjacencies because a database dump on a large core runs to megabytes
    # per router and an operator may leave it off. Short, because these
    # labels are factcheck vocabulary and are capped in length.
    "lsdb": "IGP LSDB",
    "bgp": "BGP",
    "vpnv4": "VPNv4 BGP",
    "routing": "Routing tables",
    "ldp": "MPLS LDP",
    "bfd": "BFD",
    # Two Segment Routing keys, deliberately. `sr` is SR-MPLS — an SRGB and
    # labels — and `srv6` is locators and SIDs in the IPv6 data plane. A
    # network can run either, both or neither, and a document that read one
    # and reported the other would be wrong about the data plane itself.
    #
    # Named "SR-MPLS" rather than "Segment Routing" now that it has a sibling:
    # the bare name stopped being unambiguous the moment SRv6 was added. These
    # labels are also factcheck's tool vocabulary, which is capped in length so
    # that a protocol name can never be long enough to mask an address.
    "sr": "SR-MPLS",
    "srv6": "SRv6",
    "multicast": "Multicast and MVPN",
    "ptp": "PTP",
    "lag": "Link aggregation",
    # The access layer: VLANs, trunks, spanning tree and the MAC table.
    "switching": "Switching",
    "l3vpn": "Layer 3 VPN",
    "l2vpn": "Layer 2 VPN",
    "evpn": "EVPN and VXLAN",
    "mplste": "MPLS TE tunnels",
    "srte": "SR-TE policies",
    "qos": "QoS policies",
    "security": "Firewalls",
    "management": "Management plane",
}


def feature_label(key: str) -> str:
    return FEATURE_LABELS.get(key, key)


# The single probe form DiscoNet understands. A probe is not a show command,
# so it is deliberately not expressible through CommandPolicy: it lives in its
# own allowlist, is off by default, and takes exactly one substitution.
PROBE_TEMPLATE = "ping {addr}"

# Per device, so an unexpectedly large ARP table cannot turn into a flood.
DEFAULT_PROBE_LIMIT = 20
DEFAULT_PROBE_TIMEOUT = 30

# The per-VRF forms DiscoNet understands. A VRF's ARP table is its own on
# IOS-XE and IOS-XR, and neither OS has an all-VRFs form of the command, so
# it is rendered once per VRF. Like the probe, the template is fixed and
# takes exactly one substitution: a VRF name this collection itself read,
# from the configuration or the VRF table, and held to the characters a
# VRF name is made of. Nothing else can be rendered.
PER_VRF_TEMPLATES = ("show ip arp vrf {vrf}", "show arp vrf {vrf} detail")
VRF_NAME = re.compile(r"[A-Za-z0-9_.:\-]{1,64}")
# Per device: a PE carries hundreds of VRFs, and each table is one command.
DEFAULT_VRF_LIMIT = 250
# Why a VRF's tables were not read, as the manifest records it against the
# VRF and the gap list repeats it.
VRF_LIMIT_REACHED = "more VRFs were declared than the {limit} a device is read for"
VRF_NAME_REFUSED = "the name holds a character no per-VRF command is rendered with"
# Where the VRF names come from: the stanza each platform declares one with
# (`Platform.vrf_declaration`) and the VRF table where the l3vpn group was
# collected.
VRF_TABLE_COMMANDS = ("show vrf detail", "show vrf all detail")


class CommandNotAllowed(RuntimeError):
    """Raised when a command outside the allowlist would be sent to a device."""


class CollectionError(RuntimeError):
    """Raised for unrecoverable collection problems (bad testbed, bad file, ...)."""


class SecondEnableError(CollectionError):
    """Raised when the login succeeded and the second enable did not.

    Kept distinct from a failed connect because the two send you to opposite
    ends of the problem: one is the network, the port or the credentials, the
    other is privilege on a device that already let you in.
    """


# --------------------------------------------------------------------------
# Allowlist
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OsPlan:
    """The commands allowlisted for one network OS.

    ``parse`` and ``raw_only`` are collected from every device. ``features``
    holds the optional groups, each validated exactly as strictly; which of
    them are sent is decided per run by the collect-time selection.
    """

    os: str
    parse: tuple[str, ...]
    raw_only: tuple[str, ...]
    probe: tuple[str, ...] = ()
    features: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # Templates rendered once per VRF the collection read; see PER_VRF_TEMPLATES.
    per_vrf: tuple[str, ...] = ()

    @property
    def feature_commands(self) -> dict[str, tuple[str, ...]]:
        return dict(self.features)

    @property
    def commands(self) -> tuple[str, ...]:
        """Every command this OS is allowed to be sent, feature groups included.

        This is what gates a send. Narrowing the selection removes commands
        from the plan a run executes; it never adds one that is not here.
        """
        extra = tuple(command for _, group in self.features for command in group)
        return self.parse + self.raw_only + extra

    def selected_parse(self, features: Iterable[str] | None) -> tuple[str, ...]:
        """Base commands plus the selected feature groups, in allowlist order.

        ``None`` means every group, which is what a run with no selection and
        no menu does — the tool's behaviour without an answer is to collect
        everything rather than quietly skip a protocol.
        """
        wanted = ALL_FEATURES if features is None else tuple(features)
        commands = list(self.parse)
        for key, group in self.features:
            if key not in wanted:
                continue
            for command in group:
                if command not in commands:
                    commands.append(command)
        return tuple(commands)


class CommandPolicy:
    """The show-command allowlist, keyed by OS.

    Validation happens at load time, so a malformed ``commands.yaml`` fails
    before any device is contacted.
    """

    def __init__(self, raw: dict[str, Any], source: Path | str = "<memory>"):
        self.source = str(source)
        # The SHA-256 of the exact bytes the allowlist was parsed from, set by
        # :meth:`load`. A policy built in memory was read from no file, so it
        # has no hash, rather than one of a file that may say something else.
        self.sha256: str | None = None
        self._plans: dict[str, OsPlan] = {}

        if not isinstance(raw, dict) or not raw:
            raise CollectionError(
                f"{self.source}: expected a non-empty mapping of OS -> command lists"
            )

        for os_name, spec in raw.items():
            if not isinstance(spec, dict):
                raise CollectionError(
                    f"{self.source}: OS '{os_name}' must map to 'parse' and 'raw_only' lists"
                )
            parse = self._validated_list(os_name, "parse", spec.get("parse"))
            raw_only = self._validated_list(os_name, "raw_only", spec.get("raw_only"))
            probe = self._validated_probe_list(os_name, spec.get("probe"))
            features = self._validated_features(os_name, spec.get("features"))
            per_vrf = self._validated_per_vrf_list(os_name, spec.get("per_vrf"))
            if not parse and not raw_only and not features:
                raise CollectionError(f"{self.source}: OS '{os_name}' lists no commands")
            self._plans[str(os_name)] = OsPlan(
                str(os_name), parse, raw_only, probe, features, per_vrf=per_vrf
            )

    def _validated_per_vrf_list(self, os_name: str, value: Any) -> tuple[str, ...]:
        """The per-VRF templates, each one of the fixed forms and nothing else."""
        if value is None:
            return ()
        if not isinstance(value, list):
            raise CollectionError(f"{self.source}: {os_name}.per_vrf must be a list")
        for template in value:
            if template not in PER_VRF_TEMPLATES:
                raise CommandNotAllowed(
                    f"{self.source}: {os_name}.per_vrf: {template!r} is not a supported "
                    f"per-VRF command. Permitted: {', '.join(repr(t) for t in PER_VRF_TEMPLATES)}."
                )
        return tuple(value)

    def _validated_features(
        self, os_name: str, value: Any
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        """Optional groups, held to the same rule as `parse` and named from a
        fixed set — an unrecognised key would silently never be collectable,
        because nothing in the menus or the document would ever ask for it."""
        if value is None:
            return ()
        if not isinstance(value, dict):
            raise CollectionError(
                f"{self.source}: {os_name}.features must be a mapping of "
                f"feature name -> command lists"
            )
        unknown = sorted(set(map(str, value)) - set(ALL_FEATURES))
        if unknown:
            raise CollectionError(
                f"{self.source}: {os_name}.features: unknown feature(s) "
                f"{', '.join(unknown)} (known: {', '.join(ALL_FEATURES)})"
            )
        groups: list[tuple[str, tuple[str, ...]]] = []
        for key in ALL_FEATURES:  # fixed order, so a plan is reproducible
            spec = value.get(key)
            if spec is None:
                continue
            if not isinstance(spec, dict):
                raise CollectionError(
                    f"{self.source}: {os_name}.features.{key} must map to a 'parse' list"
                )
            commands = self._validated_list(os_name, f"features.{key}.parse", spec.get("parse"))
            if commands:
                groups.append((key, commands))
        return tuple(groups)

    def _validated_probe_list(self, os_name: str, value: Any) -> tuple[str, ...]:
        """Probe templates are checked against one literal form and nothing else.

        This list is not part of the show-command allowlist and is never
        consulted unless reachability verification is explicitly requested.
        """
        if value is None:
            return ()
        if not isinstance(value, list):
            raise CollectionError(f"{self.source}: {os_name}.probe must be a list")
        for template in value:
            if template != PROBE_TEMPLATE:
                raise CommandNotAllowed(
                    f"{self.source}: {os_name}.probe: {template!r} is not a supported probe. "
                    f"The only permitted entry is {PROBE_TEMPLATE!r}."
                )
        return tuple(value)

    def _validated_list(self, os_name: str, key: str, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise CollectionError(f"{self.source}: {os_name}.{key} must be a list")
        for command in value:
            self._validate_command(os_name, key, command)
        return tuple(self.normalise(command) for command in value)

    def _validate_command(self, os_name: str, key: str, command: Any) -> None:
        where = f"{self.source}: {os_name}.{key}"
        if not isinstance(command, str) or not command.strip():
            raise CommandNotAllowed(f"{where}: commands must be non-empty strings")
        if any(ch in command for ch in ";|&<>`$\n\r"):
            raise CommandNotAllowed(f"{where}: '{command}' contains a shell/pipe metacharacter")
        # A control character is a key the CLI acts on, not text: ^U and ^W
        # erase what was typed before them, so 'show version^Uwrite memory'
        # arrives as 'write memory'. Only printable ASCII is ever sent.
        if not re.fullmatch(r"[ -~]+", self.normalise(command)):
            raise CommandNotAllowed(f"{where}: {command!r} contains a control or non-ASCII character")
        words = self.normalise(command).split()
        if words[0] != "show":
            raise CommandNotAllowed(
                f"{where}: '{command}' is not a show command — refusing to load"
            )
        forbidden = CONFIG_TOKENS.intersection(words)
        if forbidden:
            raise CommandNotAllowed(
                f"{where}: '{command}' contains non-read-only keyword(s): "
                f"{', '.join(sorted(forbidden))}"
            )

    @staticmethod
    def normalise(command: str) -> str:
        """Collapse whitespace and lowercase so allowlist checks are stable."""
        if not isinstance(command, str):
            raise CommandNotAllowed(f"command must be a string, got {type(command).__name__}")
        return re.sub(r"\s+", " ", command).strip().lower()

    @classmethod
    def load(cls, path: Path | str = DEFAULT_COMMANDS_FILE) -> "CommandPolicy":
        """Read, hash and validate the allowlist at ``path``.

        The file is read once, and the bytes that are hashed are the bytes
        that are parsed. Hashed from a second read, the record could name a
        file edited between the two, and the hash the manifest keeps is how
        an export shows which allowlist the run was held to.
        """
        path = Path(path)
        if not path.is_file():
            raise CollectionError(f"command allowlist not found: {path}")
        data = path.read_bytes()
        try:
            loaded = yaml.safe_load(data.decode("utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            raise CollectionError(f"command allowlist {path} is not readable YAML: {exc}") from exc
        policy = cls(loaded, source=path)
        policy.sha256 = hashlib.sha256(data).hexdigest()
        return policy

    @property
    def os_names(self) -> tuple[str, ...]:
        return tuple(self._plans)

    def plan_for(self, os_name: str) -> OsPlan:
        if os_name not in self._plans:
            raise CollectionError(
                f"no allowlist entry for OS '{os_name}' in {self.source} "
                f"(known: {', '.join(self.os_names)})"
            )
        return self._plans[os_name]

    def allowed_commands(self, os_name: str) -> set[str]:
        return set(self.plan_for(os_name).commands)

    def assert_allowed(self, os_name: str, command: str) -> str:
        """Gate every command sent to a device. Returns the command unchanged."""
        if self.normalise(command) not in self.allowed_commands(os_name):
            raise CommandNotAllowed(
                f"command not in allowlist for os '{os_name}': {command!r} "
                f"(allowlist: {self.source})"
            )
        return command

    def features_for(self, os_name: str) -> tuple[str, ...]:
        """Feature groups this OS actually has commands for."""
        return tuple(key for key, _ in self.plan_for(os_name).features)

    @property
    def available_features(self) -> tuple[str, ...]:
        """Every feature group any OS in the allowlist offers, in menu order.

        The menus are built from this rather than from the fixed catalogue, so
        an allowlist that drops a group stops offering it instead of offering a
        choice that would collect nothing.
        """
        found = {key for plan in self._plans.values() for key, _ in plan.features}
        return tuple(key for key in ALL_FEATURES if key in found)

    def probes_enabled_for(self, os_name: str) -> bool:
        return bool(self.plan_for(os_name).probe)

    def render_per_vrf(self, os_name: str, template: str, vrf: str) -> str:
        """Build one per-VRF show command for a VRF name the collection read.

        Three checks: the OS lists the template, the name is made only of
        the characters a VRF name is made of, and the rendered command
        matches the fixed form again. Whitespace, a pipe, a quote or an
        option cannot get through, so the command can only ever be the
        template with one bare name in it.
        """
        plan = self.plan_for(os_name)
        if template not in plan.per_vrf:
            raise CommandNotAllowed(
                f"per-VRF command {template!r} is not enabled for os '{os_name}' in {self.source}"
            )
        name = str(vrf).strip()
        if not VRF_NAME.fullmatch(name):
            raise CommandNotAllowed(f"refusing to render a per-VRF command for {vrf!r}: not a VRF name")
        command = template.format(vrf=name)
        if not re.fullmatch(r"show (?:ip )?arp vrf [A-Za-z0-9_.:\-]{1,64}(?: detail)?", command):
            raise CommandNotAllowed(f"refusing to send malformed per-VRF command {command!r}")
        return command

    def render_probe(self, os_name: str, address: str) -> str:
        """Build one ping command for a validated IP address.

        Two independent checks stand between an address and a device: the OS
        must list a probe template, and the address must survive
        ``ipaddress.ip_address``. A hostname, an option string or anything
        carrying whitespace fails here, so the rendered command can only ever
        be ``ping <literal address>``.
        """
        plan = self.plan_for(os_name)
        if not plan.probe:
            raise CommandNotAllowed(
                f"reachability probes are not enabled for os '{os_name}' in {self.source}"
            )
        try:
            parsed = ipaddress.ip_address(str(address).strip())
        except ValueError as exc:
            raise CommandNotAllowed(
                f"refusing to probe {address!r}: not an IP address ({exc})"
            ) from exc

        command = PROBE_TEMPLATE.format(addr=parsed.compressed)
        # Belt and braces: the rendered string is re-checked, so a future edit
        # to the template cannot smuggle anything past this point.
        if not re.fullmatch(r"ping [0-9a-fA-F.:]+", command):
            raise CommandNotAllowed(f"refusing to send malformed probe {command!r}")
        return command


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------

REDACTION_MARKER = "<REDACTED BY DISCONET>"

# Any line carrying one of these keywords loses everything after the keyword.
# The value must be whitespace-separated, so a bare directive such as
# "service password-encryption" carries no secret and is left intact. The
# grammar is read where the same word means two things: `key chain X` names
# a chain and `key 1` numbers a key inside it, `pre-shared-key key-chain X`
# names a chain, `authentication md5 key-chain X` names a chain, and so does
# IOS-XR's one-word `lsp-password keychain X`, while `key X`, `pre-shared-key
# X` and `authentication text X` carry the secret. An ESP transform names its
# cipher, and for AES its size, before the key: `esp aes-cbc 128 KEY` on
# IOS-XE, `esp aes 192 clear KEY` on IOS-XR. The size is only ever 128, 192
# or 256, so a key made of digits is not taken for one. IOS-XE gives some
# credentials words of their own: the Umbrella registration `token X`, a
# Smart Licensing `idtoken X`, a PKI token's `user-pin 0 X`. A token's label
# goes with them (`crypto pki token default removal timeout 0` keeps only
# `crypto pki token`), which costs nothing anything reads. The ASA gives a
# RADIUS server's common password, under `aaa-server X (inside) host A`, a
# word of its own too: `radius-common-pw X`.
_SECRET_KEYWORDS = (
    r"password|passwd|secret|key-string|key-octet-string(?:\s+\d)?|key|md5|sha(?:-?\d+)?"
    r"|(?:id)?token|user-pin|radius-common-pw"
    r"|hmac-sha-\d+(?:\s+\d)?|authentication-key|trap-group|text-authentication"
    r"|(?:standby|vrrp|glbp|hsrp)\s+\d+\s+authentication(?:\s+text)?"
    r"|authentication\s+text|ip\s+nhrp\s+authentication|wpa-psk\s+ascii(?:\s+\d)?"
    r"|cak|community-name|community-map"
    r"|esp\s+(?:3des|des|null|aes(?:-cbc)?(?:-\d+|\s+(?:128|192|256))?)"
)
# The chain is read as one only after a keyword that takes one, in the
# spelling its platform writes: `key chain X` opens a statement of its own,
# so only at the start of the line; `pre-shared-key key-chain X` and
# `authentication md5 key-chain X` (an FHRP group's too) on IOS-XE and NX-OS;
# `lsp-password keychain X` and `hello-password keychain X` on IOS-XR; a BFD
# template's `authentication sha-1 keychain X` (md5, and the meticulous
# forms, alike) on IOS-XE and NX-OS. After
# any other keyword the same word is the secret: `username bob password
# keychain` sets the password `keychain`.
_NAMES_A_CHAIN = (
    r"(?<=^key)\s+chain"
    r"|(?<=pre-shared-key)\s+key-chain"
    r"|(?<=\bmd5)\s+key-chain"
    r"|(?<=authentication)\s+md5\s+key-chain"
    r"|(?:(?<=\blsp-password)|(?<=\bhello-password))\s+keychain"
    r"|(?:(?<=\bmd5)|(?<=\bsha-1))\s+keychain"
)
SECRET_LINE = re.compile(
    r"^(?P<keep>.*?\b(?:" + _SECRET_KEYWORDS + r"))\b"
    r"(?!(?:" + _NAMES_A_CHAIN + r")\b)"
    r"(?P<value>\s+\S.*)$",
    re.IGNORECASE,
)
# A BGP peer-group, template or group is named by the operator, and a name
# such as `IBGP-MD5` or `RR-KEY` ends in a keyword: read as one, `neighbor
# IBGP-MD5 route-reflector-client` lost the flag that names a reflector's
# clients. Where the keyword falls inside the name, the line is read again
# with the name masked, so what follows it is judged on its own words.
_BGP_NAME = re.compile(
    r"^(?P<head>\s*(?:neighbor\s+\S+\s+(?:peer-group|inherit\s+peer(?:-policy|-session)?)"
    r"|neighbor|neighbor-group|af-group|session-group|peer-group"
    r"|template\s+peer(?:-policy|-session)?"
    r"|(?:use|inherit)\s+(?:neighbor-group|af-group|session-group|peer(?:-policy|-session)?))\s+)(?P<name>\S+)",
    re.IGNORECASE,
)
# A routing policy's objects are named by the operator in the same way, and
# `EXPORT-KEY`, `RT-MD5` or `PL-TOKEN` ends in a keyword just as well: read
# as one, `route-map EXPORT-KEY permit 10` lost its sequence, and Junos
# `community RT-KEY members target:65000:10;` the route target every VRF
# exporting through it is read from. A name stands after the word that
# introduces it: a route-map, prefix-list, community or extcommunity list,
# as-path list, IOS-XR route-policy or set, Junos policy-statement and
# community; the same name where a neighbour, a redistribution, a VRF's
# `import map` and `export map`, a `set extcommunity` or a Junos `from
# community` and `vrf-import` take it; and every name a route-map's `match`
# lists, to the end of its line. A Junos list in brackets is one name for
# this. The community of an SNMP statement is never such a name: it is the
# secret, and stands after `snmp-server community`, which no form below is.
# A Junos configuration group is named the same way, `ISIS-MD5`, `RR-KEY`
# or `NTP-SECRET` (R2), and `apply-groups [ ISIS-MD5 RR-KEY BASE ];` lost
# every group after the first, so which groups a level of the hierarchy
# takes could not be read; `apply-groups-except` names them alike. The
# group's own definition, `ISIS-MD5 {` (or `inactive: ISIS-MD5 {`), was
# never cut: what follows the keyword there is the brace alone, which is
# structure and stays (see redact), so the block still opens and closes.
# An IPsec transform set is named the same way, and `esp-aes-sha` or
# `TS-AES256-SHA512` ends in a keyword: `crypto ipsec transform-set
# esp-aes-sha esp-aes esp-sha-hmac` lost every transform (bug 6). The line
# gives no secret, and with the name masked its transforms are judged on
# their own words, none of which is a keyword followed by a value.
# A key chain is named the same way, `ISIS-KEY` or `OSPF-MD5`, after each
# spelling _NAMES_A_CHAIN reads as naming one: `lsp-password keychain
# ISIS-KEY level 2` lost its level, and with it the reader of the line lost
# the whole statement (G22). With the name masked the level is judged on its
# own words. A secret spelled like a chain (`password keychain`) is still
# cut: the keyword stands before the name, not inside it.
_POLICY_NAME = re.compile(
    r"(?<![\w-])(?="
    r"(?:route-map|route-policy|prefix-list|filter-list|table-map|apply-groups(?:-except)?|apply|transform-set"
    r"|ip\s+(?:ext)?community-list(?:\s+(?:standard|expanded))?|ip\s+as-path\s+access-list"
    r"|prefix-set|as-path-set|community-set|extcommunity-set\s+\S+"
    r"|policy-statement|as-path|community(?=\s+\S+\s+members\b)|community\s+(?:add|delete|set)"
    r"|(?:import|export)(?:\s+ipv[46]\s+unicast(?:\s+\d+)?)?\s+map|(?:vrf-|instance-)?(?:import|export)"
    r"|(?:from|then)\s+(?:community|policy|prefix-list|as-path)"
    r"|set\s+(?:(?:ext)?comm-list|(?:ext)?community(?:\s+rt)?)"
    r"|(?:destination|source|as-path|community|extcommunity\s+\S+)\s+(?:in|matches-(?:any|every|within))"
    r"|key\s+chain|key-chain|keychain"
    r")\s+(?P<name>\[[^\]]*\]|[^\s;]+))"
    r"|^\s*match\s+(?:ipv?6?\s+address\s+prefix-list|(?:ext)?community|as-path)\s+(?P<names>.*\S)",
    re.IGNORECASE,
)


# An IKEv2 profile's `authentication local|remote eap [gtc|md5|mschapv2]
# [username <u>] [password [0|6] <p>]` (Cisco IOS XE Security Command
# Reference, `authentication (IKEv2 profile)`) names the EAP method `md5`,
# and read as the keyword it cut the username and left `eap md5 <marker>`
# (BUG-COLLECTOR-EAP-MD5-CUT). There `md5` is a method word, as it is before
# `key-chain`: the line is read on, so `password` still cuts the password and
# a line without one is kept whole. Only the method word itself, right after
# `eap` in a line of that grammar's shape: `md5` anywhere else (a username
# that is `md5`, a hash on another crypto line), and `eap md5` followed by
# anything but `username <u>` and `password ...` (`eap md5 <value>`, which
# no documented form gives), is the keyword it always was. The marker may end
# the shape, so a second pass over `eap md5 username md5 <marker>` (a
# username that is a keyword is cut where it stands) changes nothing.
_EAP_MD5_METHOD = re.compile(
    r"^(?P<method>\s*authentication\s+(?:local|remote)\s+eap\s+md5)"
    r"(?:\s+username\s+\S+)?(?:\s+password(?:\s.*)?|\s+" + re.escape(REDACTION_MARKER) + r")?\s*$",
    re.IGNORECASE,
)


def _object_names(line: str) -> list[tuple[int, int]]:
    """The spans of the names an operator gave on this line: a BGP group's (_BGP_NAME), a policy's (_POLICY_NAME).

    A Junos configuration group's, after `apply-groups`, is a policy's for this.
    """
    spans = []
    named = _BGP_NAME.match(line)
    if named:
        spans.append(named.span("name"))
    for found in _POLICY_NAME.finditer(line):
        group = "name" if found.group("name") is not None else "names"
        spans.append(found.span(group))
    return spans


def _secret_line(line: str) -> re.Match[str] | None:
    """SECRET_LINE's match, but not on a keyword inside a name (see _BGP_NAME and _POLICY_NAME).

    The match it returns is on the line with the names masked, which has the
    same length, so its spans are the line's. Each name the keyword falls in
    is masked in turn, so a keyword after it is still found.
    """
    match = SECRET_LINE.match(line)
    spans = _object_names(line) if match else []
    masked = line
    while match:
        # `eap md5` is a method there, as `md5` before `key-chain` is (see
        # _EAP_MD5_METHOD): masked, the line is judged on the words after it.
        method = _EAP_MD5_METHOD.match(line)
        if method and method.end("method") == match.end("keep"):
            end = match.end("keep")
            masked = masked[: end - 3] + "xxx" + masked[end:]
            match = SECRET_LINE.match(masked)
            continue
        inside = next(((start, end) for start, end in spans if start < match.end("keep") <= end), None)
        if inside is None:
            return match
        start, end = inside
        # A keyword standing as the whole word is the keyword: IOS-XR's
        # `neighbor password encrypted X` under LDP gives the password. It
        # stands as a word where the name has it at its start or after a
        # space or a bracket, not only where it is the name from its start: a
        # Junos list in brackets is one name, and `apply-groups [ x password
        # hunter2 ];` read from its `[` was never the keyword alone, so the
        # whole list was masked and the word after `password` kept. A keyword
        # of more than one word (`authentication text`, `wpa-psk ascii 0`) is
        # matched whole, not by its last word.
        if re.search(rf"(?:^|[\s\[])(?:{_SECRET_KEYWORDS})$", line[start: match.end("keep")], re.IGNORECASE):
            return match
        masked = masked[:start] + "x" * (end - start) + masked[end:]
        spans.remove(inside)
        match = SECRET_LINE.match(masked)
    return None


# `key 1` under a key chain: an identifier, not a secret. Only a bare `key`
# followed by nothing but digits, and only inside `key chain X`. The same line
# under `radius server X` or `tacacs server X` is the shared secret, written
# in clear, and a numeric one is still a secret.
_KEY_ID_LINE = re.compile(r"^\s*key\s+\d+\s*$", re.IGNORECASE)
_KEY_CHAIN = re.compile(r"^key\s+chain\b", re.IGNORECASE)
# Junos numbers a chain's key the same way and opens a block on it, `key 1 {`
# inside `key-chain X { }`, with the secret on a line of its own below it.
_JUNOS_KEY_ID_LINE = re.compile(r"^\s*key\s+\d+\s*\{\s*$", re.IGNORECASE)
# `ntp trusted-key 1` names the keys an association may use, by number, on
# every platform: IOS-XR indents it under `ntp`, Junos writes `trusted-key [
# 1 2 ];` inside `ntp { }`, IOS a range `1 - 3`. Nothing but numbers follows
# it; a line with a word after them is read as any other.
_NTP_TRUSTED_KEY = re.compile(r"^\s*(?P<ntp>ntp\s+)?trusted-key\s+\[?[\d\s-]*\d[\d\s-]*\]?\s*;?\s*$", re.IGNORECASE)
# `ntp server 192.0.2.1 key 1 prefer source Loopback0`: the number names a key
# configured under `ntp authentication-key`, which is where the secret is, and
# what follows it (the preference, the source, the VRF) is the association's.
# IOS-XE, NX-OS and ASA say `ntp server`; IOS-XR indents `server` under `ntp`
# and Junos writes it inside `ntp { }`. `server-private` is a TACACS server,
# whose key is the secret, and is not an association.
_NTP_ASSOCIATION = re.compile(r"^\s*(?P<ntp>ntp\s+)?(?:server|peer)\s", re.IGNORECASE)
_NTP_KEY_NUMBER = re.compile(r"\s+\d+(?:[\s;]|$)")
# IOS-XR writes an HSRP group's plain-text string as a bare `authentication
# XrHsrp1` under `hsrp 1`, with no `text` in front to say what it is. One
# word after `authentication` is such a string unless it is one of the modes
# the same word takes elsewhere: `authentication message-digest` under XR
# OSPF, `authentication open` on an 802.1X port, a Junos block's brace. The
# method of an IKEv1 policy (`crypto isakmp policy`, the ASA's `crypto ikev1
# policy`) is one too, and so are a dot11 SSID's `shared` and XR OSPFv3's
# `disable`: redacting them took the IKE method out of the security reading.
# So is IOS-XE's `send-only` under `router isis` (R3): `authentication
# send-only` sends the key the instance's `authentication key-chain X` names
# and does not yet check what arrives, a migration step an assessment must
# see, and it read as the HSRP string. With a level after it (`send-only
# level-2`), and as an interface's `isis authentication send-only`, the line
# is no bare `authentication` and was always kept. Bare, it is a mode only
# under `router isis`; under anything else (an HSRP group on IOS-XR) the word
# is read as the string it would be there, and cut.
_BARE_AUTHENTICATION = re.compile(r"^(?P<keep>\s*authentication)(?P<value>\s+(?P<word>\S+))\s*$", re.IGNORECASE)
_ROUTER_ISIS = re.compile(r"^router\s+isis\b", re.IGNORECASE)
_AUTHENTICATION_MODES = frozenset({
    "message-digest", "null", "md5", "text", "keychain", "key-chain",
    "open", "periodic", "aaa", "certificate", "saml", "{",
    "pre-share", "rsa-sig", "rsa-encr", "ecdsa-sig", "crack", "shared", "disable",
    "send-only",
})
# A line that says how a peer or a login is authenticated, not with what,
# though a keyword stands in it: IS-IS's `authentication mode md5 level-2`
# (the key is in the chain the next line names), `mpls ldp password required
# [for ACL]` (a neighbour must give one, set elsewhere), Junos's
# `authentication-order [ password radius ];` (local passwords, then RADIUS).
# Every word after the keyword belongs to the grammar, so the whole line is
# matched, and a line with one word more is read by the keyword rules.
_A_MODE_LINE = re.compile(
    r"^\s*(?:isis\s+)?authentication\s+mode\s+(?:md5|text)\s+level-[12]\s*$"
    r"|^\s*mpls\s+ldp\s+password\s+required(?:\s+for\s+\S+)?\s*$"
    r"|^\s*authentication-order\s+\[(?:\s*(?:password|radius|tacplus|ldaps))+\s*\]\s*;\s*$",
    re.IGNORECASE,
)
# A line that switches how keys and passwords are handled and gives none
# (R5). NX-OS's `ssh key rsa 2048` (`dsa`, `ecdsa 521`, `force` after it)
# says which host key the switch generates, which `ssh key <REDACTED>` hid;
# its `password strength-check` and `no password strength-check` turn the
# check on new passwords on or off, and `no password <REDACTED>` could not
# say which; `feature password encryption aes` on NX-OS and `password
# encryption aes` on IOS-XE store passwords encrypted with the master key,
# which is set by `key config-key password-encrypt X` (redacted as any key)
# and never shown. Only these shapes are kept whole; a word more and the line
# is read by the keyword rules. All three are global commands and stand at the
# start of the line, and only there are they kept: indented, `password
# strength-check` is a line's password under `line vty 0 4` (IOS takes the
# rest of the line as one, spaces and all, so ` password encryption aes` is
# one too), and it is cut as any password. Text with no indentation to tell
# the two apart is never kept on this rule: a command an EEM action or a Junos
# event policy types (`action 4.0 cli command "password strength-check"`
# after `"line vty 0 4"`), and an IOS macro's body, which `macro name X`
# prints at the start of the line up to its `@`.
_MACRO_NAME = re.compile(r"^macro\s+name\s+\S+\s*$", re.IGNORECASE)
_A_SETTING_LINE = re.compile(
    r"^ssh\s+key\s+(?:rsa|dsa|ecdsa)(?:\s+\d{3,4})?(?:\s+force)?\s*$"
    r"|^(?:no\s+)?password\s+strength-check\s*$"
    r"|^(?:feature\s+)?password\s+encryption\s+aes\s*$",
    re.IGNORECASE,
)
# An SSH server's algorithm lists name ciphers, MACs, key exchanges and host
# keys, and many of the names end in a keyword: `hmac-sha1`, `hmac-md5`,
# `diffie-hellman-group14-sha256`, and IOS-XR's head `host-key` is one
# itself. Read as one, `ip ssh server algorithm mac hmac-sha1 hmac-sha2-256`
# kept the first MAC of two, Junos's `macs [ hmac-sha2-256 hmac-sha1 ];` lost
# its bracket with them and `ssh server algorithms host-key ecdsa-nistp256
# rsa` every key, so which algorithms the server offers could not be read
# (R1). A statement whose every word after its head is a name that head
# takes, from the closed lists below, is kept whole; one word that is no such
# name (a secret typed after the list, a cipher in a list of MACs, a quoted
# string that is no list) and the line is read by the keyword rules as before.
# The names are OpenSSH's, with the vendors' own spellings: Junos's and the
# ASA's key exchanges (`dh-group14-sha1`, `group-exchange-sha2`,
# `ecdh-group19`), IOS-XR's host keys (`rsa`, `dsa`, `ecdsa-nistp256`,
# `ed25519`), Junos's (`ssh-ecdsa`, `no-ssh-dss`), and the level the ASA and
# NX-OS let stand for a list (`ssh cipher integrity high`, `ssh macs all`).
_SSH_CIPHERS = (
    r"aes(?:128|192|256)-(?:ctr|cbc)|aes(?:128|256)-gcm(?:@openssh\.com)?|3des-cbc"
    r"|chacha20-poly1305@openssh\.com|arcfour(?:128|256)?|blowfish-cbc|cast128-cbc"
)
_SSH_MACS = (
    r"hmac-(?:sha1|md5)(?:-96)?(?:-etm@openssh\.com)?|hmac-sha2-(?:256|512)(?:-etm@openssh\.com)?"
    r"|hmac-ripemd160(?:-etm@openssh\.com)?|umac-(?:64|128)(?:-etm)?@openssh\.com"
)
_SSH_KEX = (
    r"(?:diffie-hellman|dh)-group(?:1|14|15|16|17|18)-sha(?:1|256|512)"
    r"|diffie-hellman-group-exchange-sha(?:1|256)|group-exchange-sha[12]"
    r"|ecdh-sha2-nistp(?:256|384|521)|ecdh-group(?:19|20|21)"
    r"|curve25519-sha256(?:@libssh\.org)?|sntrup761x25519-sha512(?:@openssh\.com)?"
)
_SSH_HOST_KEYS = (
    r"ssh-rsa|ssh-dss|rsa-sha2-(?:256|512)|ecdsa-sha2-nistp(?:256|384|521)|ssh-ed25519"
    r"|x509v3-(?:ssh-rsa|ssh-dss|rsa2048-sha256|ecdsa-sha2-nistp(?:256|384|521))"
)
_XR_HOST_KEYS = _SSH_HOST_KEYS + r"|rsa|dsa|ecdsa-nistp(?:256|384|521)|ed25519"
_JUNOS_HOST_KEYS = r"(?:no-)?ssh-(?:rsa|dss|ecdsa|ed25519)"
# IOS-XE's `ip ssh server algorithm authentication` lists the user
# authentication methods the server offers, and `password` is one of them.
_SSH_METHODS = r"publickey|password|keyboard"


def _ssh_names(names: str) -> str:
    """One name or more of `names`, a space between each."""
    return rf"(?:{names})(?:\s+(?:{names}))*"


def _junos_ssh_names(names: str) -> str:
    """Junos's value: one name, or a list of them in brackets, then the semicolon."""
    return rf"(?:(?:{names})|\[\s*{_ssh_names(names)}\s*\])\s*;"


def _asa_ssh_setting(names: str) -> str:
    """The ASA's value: a level, or `custom` and a colon-separated list of names, in quotes or not."""
    listed = rf"(?:{names})(?::(?:{names}))*"
    return rf'(?:all|fips|high|low|medium|custom\s+(?:{listed}|"{listed}"))'


# The heads, each with the names it takes. IOS-XE says `ip ssh server
# algorithm encryption|mac|kex|hostkey|publickey|authentication` and `ip ssh
# client algorithm encryption|mac|kex`; IOS-XR `ssh server algorithms` and
# `ssh client algorithms`, then `cipher`, `mac`, `key-exchange` or
# `host-key`; NX-OS `ssh ciphers|macs|kexalgos|keytypes`, a list or `all`;
# the ASA `ssh key-exchange group` and `ssh cipher encryption|integrity`.
# Junos's heads are below: alone they are common words.
_SSH_ALGORITHM_LINE = re.compile(
    "|".join(
        rf"^\s*{head}\s+{value}\s*$"
        for head, value in (
            (r"ip\s+ssh\s+(?:server|client)\s+algorithm\s+encryption", _ssh_names(_SSH_CIPHERS)),
            (r"ip\s+ssh\s+(?:server|client)\s+algorithm\s+mac", _ssh_names(_SSH_MACS)),
            (r"ip\s+ssh\s+(?:server|client)\s+algorithm\s+kex", _ssh_names(_SSH_KEX)),
            (r"ip\s+ssh\s+server\s+algorithm\s+(?:hostkey|publickey)", _ssh_names(_SSH_HOST_KEYS)),
            (r"ip\s+ssh\s+server\s+algorithm\s+authentication", _ssh_names(_SSH_METHODS)),
            (r"ssh\s+(?:server|client)\s+algorithms\s+cipher", _ssh_names(_SSH_CIPHERS)),
            (r"ssh\s+(?:server|client)\s+algorithms\s+mac", _ssh_names(_SSH_MACS)),
            (r"ssh\s+(?:server|client)\s+algorithms\s+key-exchange", _ssh_names(_SSH_KEX)),
            (r"ssh\s+(?:server|client)\s+algorithms\s+host-key", _ssh_names(_XR_HOST_KEYS)),
            (r"ssh\s+ciphers", rf"(?:all|{_ssh_names(_SSH_CIPHERS)})"),
            (r"ssh\s+macs", rf"(?:all|{_ssh_names(_SSH_MACS)})"),
            (r"ssh\s+kexalgos", rf"(?:all|{_ssh_names(_SSH_KEX)})"),
            (r"ssh\s+keytypes", rf"(?:all|{_ssh_names(_SSH_HOST_KEYS)})"),
            (r"ssh\s+key-exchange\s+group", _ssh_names(_SSH_KEX)),
            (r"ssh\s+cipher\s+encryption", _asa_ssh_setting(_SSH_CIPHERS)),
            (r"ssh\s+cipher\s+integrity", _asa_ssh_setting(_SSH_MACS)),
        )
    ),
    re.IGNORECASE,
)
# Junos says `ciphers`, `macs`, `key-exchange` and `hostkey-algorithm`,
# active or `inactive:`, with no `ssh` in front: the statement is SSH's
# because it stands in `system services ssh { }`, and only there is it kept
# whole (redact checks that the innermost open block is `ssh`). The same
# line anywhere else is no statement of the server's and is read by the
# keyword rules as before.
_JUNOS_SSH_ALGORITHM_LINE = re.compile(
    "|".join(
        rf"^\s*(?:inactive:\s+)?{head}\s+{value}\s*$"
        for head, value in (
            (r"ciphers", _junos_ssh_names(_SSH_CIPHERS)),
            (r"macs", _junos_ssh_names(_SSH_MACS)),
            (r"key-exchange", _junos_ssh_names(_SSH_KEX)),
            (r"hostkey-algorithm", _junos_ssh_names(_JUNOS_HOST_KEYS)),
        )
    ),
    re.IGNORECASE,
)
# A value a pass of redact has already cut is the marker, which has spaces in
# it. Where a rule takes the secret as one word, it takes the marker as one
# too, or a second pass reads `<REDACTED` as the secret and `BY DISCONET>` as
# the words after it, matches nothing, and the line falls to the keyword rule,
# which cuts what the first pass kept (bug 4). A brace is never the secret
# (see _XR_ISIS_PASSWORD).
_ONE_SECRET = rf"(?:{re.escape(REDACTION_MARKER)}|[^\s{{]\S*)"
# `crypto isakmp key X address A.B.C.D`: the key goes, the peer stays. A
# device with `service password-encryption` or `password encryption aes`
# writes the key's encryption type before it, `crypto isakmp key 6 X address
# A`; the type is kept with the keyword. Read as the key, the digit went and
# the line fell to the keyword rule, which took the peer with it. A key that
# is itself one digit (`key 6 address A`) leaves no word between the digit
# and `address`, and the digit is cut as the key it is.
_ISAKMP_KEY = re.compile(
    rf"^(?P<keep>.*\bisakmp\s+key(?:\s+[067])?)\s+(?P<value>{_ONE_SECRET})"
    r"(?P<rest>\s+address\s+.*)$",
    re.IGNORECASE,
)
# An IOS-XE keyring gives a peer its key as `pre-shared-key address A [mask]
# key K` under `crypto keyring X`. Cut at the keyword, the line lost the peer
# the key is for (bug 5). In exactly this shape, with an address (and its
# mask) written as one, everything after `key` goes, as it went before, and
# the address stays. Any other shape, `pre-shared-key hostname H key K`,
# `pre-shared-key key K`, a word that is no address, is cut at the keyword.
_LITERAL_PEER = r"(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]*(?:/\d{1,3})?)"
_KEYRING_PSK = re.compile(
    rf"^(?P<keep>\s*pre-shared-key\s+address\s+(?:ipv6\s+)?{_LITERAL_PEER}(?:\s+{_LITERAL_PEER})?\s+key)"
    r"(?P<value>\s+\S.*)$",
    re.IGNORECASE,
)
# IOS-XR writes an IS-IS password with its mode and its options on one line:
# `lsp-password hmac-md5 encrypted 0822455D0A16 level 2 send-only` under
# `router isis`, `hello-password text encrypted X` under one of its
# interfaces. Cut at the keyword, the line lost whether the password is an
# HMAC-MD5 key or clear text, its level and `send-only` (R4), so an
# assessment could not tell an authenticated level from one that only sends.
# In exactly this shape the password is the one word after `encrypted` or
# `clear`, and only it goes: `(lsp|hello)-password hmac-md5|text
# encrypted|clear X [level 1|2] [send-only] [enable-poi]`. Any other shape
# (`lsp-password accept ...`, a word more, a password quoted for its spaces)
# is cut at the keyword as before, and `keychain X` names a chain and stays
# whole (see _NAMES_A_CHAIN). A brace is never the password: IOS-XR has none,
# and a `{` taken for one would be dropped before redact tracks it, so the
# block it opens would close on the brace of the block around it.
_XR_ISIS_PASSWORD = re.compile(
    rf"^(?P<keep>\s*(?:lsp|hello)-password\s+(?:hmac-md5|text)\s+(?:encrypted|clear))\s+{_ONE_SECRET}"
    r"(?P<rest>(?:\s+level\s+[12])?(?:\s+send-only)?(?:\s+enable-poi)?\s*)$",
    re.IGNORECASE,
)
# An EEM variable is named by the operator, and the policies it feeds are
# scripts that log in somewhere: `_email_password`, `_tftp_pw` and `_login`
# all hold credentials, and `\b` does not even fall between the `_` and the
# keyword of the first. No list of words knows which of them is a secret, so
# every value goes and the name stays; nothing DiscoNet reads is in one.
_EEM_ENVIRONMENT = re.compile(r"^(?P<keep>\s*event\s+manager\s+environment\s+\S+)(?P<value>\s+\S.*)$", re.IGNORECASE)
# An EEM action types a whole command, `action 2.0 cli command "snmp-server
# community X RO"`, which the rules read as the action's words: none of
# them starts with `snmp`. The command between the quotes is redacted as the
# line it would be, and the action around it stays. An action that waits for
# a password prompt (`cli command "enable" pattern "[Pp]assword"`) is
# answered by the next one, whose whole command is then the password.
_EEM_CLI = re.compile(
    r'^(?P<head>\s*action\s+\S+\s+cli\s+command\s+")(?P<command>[^"]*)(?P<tail>".*)$', re.IGNORECASE
)
_EEM_ASKS_FOR_SECRET = re.compile(r'\bpattern\s+"[^"]*(?:assw|pass(?:phrase|code)|secret|\bpin\b)', re.IGNORECASE)
# The pattern is a regular expression the device matches against what it
# prints, and any fragment of the prompt matches it: `"word:"`, `"ssword"`,
# `"pass"` and `"[Pp]ass"` all wait for `Password:` and name none of the
# words above. So a pattern also asks for a secret where it would match one
# of the prompts that ask for one, case aside, as the device would read it;
# one that is no regular expression is read as the text it is. An `enable`
# (or its abbreviation, at any level) is answered by its password whatever
# its pattern says. The next answer is redacted wherever this is unsure,
# which loses one command's words; reading it the other way leaks a password.
_EEM_PATTERN = re.compile(r'\bpattern\s+"(?P<pattern>[^"]*)"', re.IGNORECASE)
_EEM_ENABLE = re.compile(r"\s*en(?:a(?:b(?:le?)?)?)?(?:\s+\d+)?\s*", re.IGNORECASE)
_SECRET_PROMPTS = tuple(
    f"{word}{end}" for word in ("Password", "Passphrase", "Passcode", "Secret", "PIN") for end in (":", ": ")
)


def _eem_asks_for_secret(command: str, tail: str) -> bool:
    """Does the EEM action typing `command`, with `tail` after it, wait for a prompt the next action answers with a secret?"""
    if _EEM_ASKS_FOR_SECRET.search(tail):
        return True
    waits = _EEM_PATTERN.search(tail)
    if not waits:
        return False
    if _EEM_ENABLE.fullmatch(command):
        return True
    try:
        pattern = re.compile(waits.group("pattern"), re.IGNORECASE)
    except re.error:
        pattern = re.compile(re.escape(waits.group("pattern")), re.IGNORECASE)
    return any(pattern.search(prompt) for prompt in _SECRET_PROMPTS)
# NX-OS types the command bare after `cli`, `local` in front of it where the
# action runs on the active supervisor: `action 2.0 cli snmp-server community
# X group network-operator`. Junos types each command of an event policy's
# `change-configuration commands { }` in quotes on a line of its own, and
# in set form after `commands`; a quote inside one is escaped. Each is
# redacted as the line it would be, as the IOS command between quotes is.
_EEM_BARE_CLI = re.compile(
    r'^(?P<head>\s*action\s+\S+\s+cli\s+(?:local\s+)?)(?P<command>(?!command\s+")\S.*?)(?P<tail>\s*)$',
    re.IGNORECASE,
)
_JUNOS_COMMAND = re.compile(r'^(?P<head>\s*")(?P<command>(?:[^"\\]|\\.)*)(?P<tail>"\s*;.*)$')
_JUNOS_SET_COMMAND = re.compile(
    r'^(?P<head>\s*set\s.*?\bcommands\s+")(?P<command>(?:[^"\\]|\\.)*)(?P<tail>".*)$', re.IGNORECASE
)
# An EEM `mail` action names the server it sends through, and Cisco
# documents `user:password@host` for it: `action 1.0 mail server
# "mailer:X@192.0.2.22" to ...`. Call Home names its SMTP relay the same
# way, `mail-server [user:password@]host priority 1` (NX-OS after `transport
# email`), so the form is read after any `mail-server` or `mail server`. The
# value has no `://`, so the URL rule below never reads it. The password
# goes and the user and the host stay; as in a URL, the password runs to the
# last `@` of the value, so one with an `@` or a `:` in it is not cut short.
# The value is quoted or one word, and one with no `@` (a host, an IPv6
# address) is no credential.
_MAIL_SERVER = re.compile(
    r'^(?P<head>.*?\bmail(?:-|\s+)server\s+(?P<quote>")?(?(quote)[^":]*|[^\s":]*):)'
    r'(?P<password>(?(quote)[^"]*|\S*))(?P<tail>@(?(quote)[^"@]*"|[^\s@]*)(?:\s.*)?)$',
    re.IGNORECASE,
)
# Credentials inside a URL: `scp://user:pass@host/path`. The host and path
# stay; the userinfo is the secret. Devices take a user name with an `@` in
# it, and a password with an `@` or a `/`, unescaped, so the userinfo runs to
# the last `@` of the URL: a `p@ss` that stopped at its first `@` kept `ss`,
# and a `pa/ss` was not read as a URL's credentials at all. A path with an
# `@` in it after a port (`tftp://192.0.2.1:69/cfg@site`) is not userinfo,
# though it has the same shape: what stands before the port is a host when
# it is an address or a dotted name, and a user name otherwise, so
# `scp://admin:1234/x@192.0.2.1/` still loses `admin:1234/x`. A dotted user
# name with a password of digits and a slash has a host's shape too
# (`scp://admin.ops:1234/x@192.0.2.1/`), and what tells the two apart is
# what follows the last `@`: after credentials it is the host, an address or
# a dotted name, whatever follows it, or any name followed by a port or a
# path; after a path it is the rest of a file name, `site` in `cfg@site`.
# So the host-and-port reading holds only where no host follows the last
# `@`, and a path whose `@` is followed by a host's shape (`cfg@site.bak`,
# `a@b/c`) loses what stands before it, which is the way to be wrong that
# leaks nothing. The user name may be empty (`ftp://:pass@host`), and a
# password quoted for the spaces in it (`scp://ops:"pa ss"@host`) runs to
# its closing quote.
_URL_HOST_PORT = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[\w-]+(?:\.[\w-]+)+):\d{1,5}/"
_URL_HOST_AFTER_LAST_AT = (
    r"\S*@(?!\S*@)(?:(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\]|[\w-]+(?:\.[\w-]+)+)(?![\w.-])|[\w-]+[/:])"
)
_URL_USERINFO = re.compile(
    rf'://(?:[^\s:/"]*:"[^"\n]*"[^\s@]*@|(?!{_URL_HOST_PORT}(?!{_URL_HOST_AFTER_LAST_AT}))[^\s:/]*:\S*@)'
)
# Junos marks every secret it prints: the whole value goes, whatever the
# statement, because the device said so. The statement is the first word,
# and it may be a URL whose credentials the pass above has already replaced
# with the marker (`"scp://<REDACTED BY DISCONET>@10.0.0.1/backups" password
# "$9$..."`): the marker's spaces are not the end of that word, or the line
# is cut inside the marker and the host after it is lost.
_JUNOS_SECRET_DATA = re.compile(
    rf"^(?P<keep>\s*(?:{re.escape(REDACTION_MARKER)}|\S)+)(?P<value>\s+.*##\s*SECRET-DATA\s*)$"
)
# Junos prints the value it marks in quotes, in one of its `$<n>$` forms
# (`$9$`, `$1$`, `$5$`, `$6$`), so on most such lines the secret can be found
# and the statement before it kept: `"ftp://host/x" password "$9$..."` keeps
# `password`, `md5 1 key "$9$..."` its key id and `key`, `pre-shared-key
# ascii-text "$9$..."` its format (BUG-COLLECTOR-JUNOS-SECRET-DATA-FIRST-WORD).
# The words before it are read as Junos reads them, quoted or not, the marker
# a pass already wrote counting as part of a word; anything else in front of
# it (an unclosed quote, a quote inside a word, a `;`, brace, bracket, `#` or
# comment) is a shape this rule does not know, and the line is cut at its
# first word as before. Everything after the secret goes, but for the `;`
# and closing braces that end the line inside a block.
_JUNOS_SECRET_VALUE = re.compile(r'"\$\d\$')
_JUNOS_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
_JUNOS_UNQUOTED = re.compile(rf'(?:{re.escape(REDACTION_MARKER)}|[^\s";{{}}\[\]#])+')
_JUNOS_GAP = re.compile(r"\s+")
_JUNOS_SECRET_DATA_END = re.compile(r"^(?P<end>\s*;(?:\s*\})*)?\s*##\s*SECRET-DATA\s*$")
# What a second pass sees of the statements the rule above keeps whole: the
# grammar words of an OSPF MD5 key, an IKE pre-shared key and an NTP key,
# then the marker and nothing else. Each word here is fixed by the grammar
# or a key number, none a secret; without this the keyword rule cut them on
# the second pass (`md5 1 key <marker>` became `md5 <marker>`), and redact
# was no longer idempotent. Only with the marker as the value: the same
# words before a value that is not the marker are cut as before.
_JUNOS_KEPT_SECRET_WORDS = re.compile(
    r"^\s*(?:(?:authentication\s+)?md5\s+\d+\s+key|pre-shared-key\s+(?:ascii-text|hexadecimal)"
    rf"|authentication-key\s+\d+\s+type\s+[a-z0-9-]+\s+value)\s+{re.escape(REDACTION_MARKER)}"
    r"(?:\s*;(?:\s*\})*)?\s*$",
    re.IGNORECASE,
)


def _junos_secret_data(line: str, in_block: bool) -> str | None:
    """A `## SECRET-DATA` line with its quoted `$n$` value replaced, or None where it has none.

    Keeps the words before the first such value and, inside a Junos block,
    the `;` and closing braces that end the line; drops the annotation. It must not keep anything
    after the value but that end, and must not guess: a line it cannot read
    word by word up to the value is None, and the caller cuts it at its
    first word as before. Outside a block the `;` goes, as it goes on every
    other line there (see _JUNOS_LEAF_END), so a second pass changes nothing.
    """
    if "/*" in line:
        return None
    position = len(line) - len(line.lstrip())
    while position < len(line):
        if line[position] == '"':
            word = _JUNOS_QUOTED.match(line, position)
            if word and _JUNOS_SECRET_VALUE.match(line, position):
                kept = line[:position].rstrip()
                # What follows the value goes. Its `;` and braces stay where
                # nothing else follows, or where what does is Junos words, the
                # shape in which _JUNOS_LEAF_END has always kept them.
                rest = line[word.end():]
                end = _JUNOS_SECRET_DATA_END.match(rest) or _JUNOS_LEAF_END.match(rest.strip())
                suffix = (end.group("end") or "") if end and in_block else ""
                # A value that is the first word keeps the indentation alone.
                return f"{kept} {REDACTION_MARKER}{suffix}" if kept else f"{line[:position]}{REDACTION_MARKER}{suffix}"
        else:
            word = _JUNOS_UNQUOTED.match(line, position)
        if not word:
            return None
        gap = _JUNOS_GAP.match(line, word.end())
        if not gap:
            return None
        position = gap.end()
    return None


# `community` is a secret only where it is an SNMP community. The same word
# names a BGP community everywhere else — a Junos `community Comm:RT:X
# members target:64512:1;` and the `community X;` a policy term matches are
# the route targets of every VRF built on policy — and a rule that redacted
# those left every such VRF on an estate with no target to be read. So the
# word redacts on a line that says `snmp` (`snmp-server community public
# RO`, an ASA host line) and inside a Junos `snmp { }` block, and nowhere
# else.
COMMUNITY_LINE = re.compile(r"^(?P<keep>.*?\bcommunity\b)(?P<value>\s+\S.*)$", re.IGNORECASE)
# A Junos leaf's value and the end of its line (see redact): one or more
# words, each quoted, unquoted with no `;`, brace, bracket or quote in it, or
# the marker a pass already wrote; then the `;`, any closing braces, and
# optionally the `## SECRET-DATA` annotation, and nothing else. The `;` and
# the braces are kept; the annotation is matched but never kept: it says which
# value was a secret, and that never reaches disk. A list in brackets is no
# such value and is cut whole, as before. Another annotation may be text an
# operator typed, and with it the line is cut as before.
_JUNOS_WORD = rf'(?:"(?:[^"\\]|\\.)*"|{re.escape(REDACTION_MARKER)}|[^\s";{{}}\[\]]+)'
_JUNOS_LEAF_END = re.compile(
    rf"^(?P<value>{_JUNOS_WORD}(?:\s+{_JUNOS_WORD})*)(?P<end>\s*;(?:\s*\}})*)(?:\s+##\s*SECRET-DATA)?\s*$"
)
# A statement that starts with `snmp`, not a line that mentions it: a BGP
# community named `SNMP-MGMT-RT` is a route target's name. Junos's set form,
# `set snmp community X`, starts with it after its verb.
_SNMP_WORD = re.compile(r"^\s*(?:set\s+)?snmp\b", re.IGNORECASE)
_JUNOS_BLOCK_OPEN = re.compile(r"^\s*(?:inactive:\s*|protect:\s*)?(?P<name>\S+)(?:\s+\S+)*\s*\{\s*$")
# Junos annotates a deprecated statement after its brace, `snmp { ## Warning:
# 'snmp' is deprecated`, and the brace still opens the block. Read without the
# annotation, so the block is tracked and its closing brace pops it, not the
# `snmp` around it. A comment after the brace, `snmp { /* NOC */`, is read
# past the same way.
_JUNOS_ANNOTATION = re.compile(r"\s+(?:##.*|/\*.*\*/\s*)$")

# A trap or inform receiver's line carries the community string with no
# keyword in front of it: `snmp-server host 192.0.2.9 version 2c public`. What
# stays is the address and how it is addressed — traps or informs, which
# version, which VRF, which source — and what follows that is the secret.
# IOS-XR indents the same line under `snmp-server vrf X` without the prefix,
# so the bare `host` form is taken too, but only once the line has said
# `traps`, `informs` or `version`, or sits under `snmp-server vrf`, where a
# host may give its community with no more than `encrypted` or `clear` in
# front of it; a Junos `host 192.0.2.9 {` does neither.
SNMP_HOST_LINE = re.compile(
    r"^(?P<keep>\s*(?P<prefix>snmp-server\s+)?host\s+\S+"
    r"(?:\s+(?:traps|informs|version\s+\S+(?:\s+(?:auth|noauth|priv))?|vrf\s+\S+|use-vrf\s+\S+"
    r"|source-interface\s+\S+|udp-port\s+\d+))*)"
    r"(?P<value>\s+\S.*)$",
    re.IGNORECASE,
)
_SNMP_HOST_SAID = re.compile(r"\b(?:traps|informs|version)\b", re.IGNORECASE)
_SNMP_VRF = re.compile(r"^snmp-server\s+vrf\s", re.IGNORECASE)
# ASA names the interface before the address, `snmp-server host inside
# 192.0.2.9 community public version 2c`, which the line above reads as host
# `inside` with everything from the address on as the secret. Keyed on the
# literal address in second place, only the community (after its optional
# 0/8 encryption digit) and a version 3 user name go; the address, poll or
# trap, the version and the port stay. The word before the address must not
# be one itself: IOS puts the address first, and a community shaped like an
# address after it (`snmp-server host 192.0.2.9 c0ff:ee`) is still the secret.
# Nor does a name in first place prove the ASA form, because IOS takes a host
# name there too: in `snmp-server host nms.example.com 10.20.30.40` the second
# word is the community. ASA says `community` or `version` on every host line
# that carries a secret, and `poll` or `trap` (IOS says `traps`) on one that
# takes the global community, so the line is read as ASA only where it says
# one of them; one that says none is read as IOS and loses its second word,
# which is the safer way to be wrong, unless the output proves it the ASA's
# (below). An IPv6 literal has two colons at least
# (a `::` is two), so a community such as `c0ff:ee` or `1:2` is not taken for
# one.
_LITERAL_ADDRESS = r"(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]*)"
_ASA_SNMP_HOST = re.compile(
    rf"^(?P<head>\s*snmp-server\s+host\s+(?!{_LITERAL_ADDRESS}\s)\S+\s+{_LITERAL_ADDRESS})"
    r"(?P<rest>\s.*\b(?:community|version|poll|trap)\b.*)$",
    re.IGNORECASE,
)
# A host line that says nothing after the address but its port, `snmp-server
# host inside 192.0.2.9`, is the ASA's where the receiver takes the global
# community: it carries no secret, and the NMS address is the management
# chapter's. It has IOS's shape all the same (`snmp-server host nms1
# 10.20.30.40`, with a community in second place), so it is read as the ASA's
# only where the first word is an interface the same output names with
# `nameif`, which IOS never says, and the second is an address that parses
# as one. Anything else loses its second word as before.
_ASA_SNMP_BARE_HOST = re.compile(
    r"^\s*snmp-server\s+host\s+(?P<nameif>\S+)\s+(?P<address>\S+)(?:\s+udp-port\s+\d+)?\s*$", re.IGNORECASE
)
_ASA_NAMEIF = re.compile(r"^\s*nameif\s+(?P<nameif>\S+)\s*$", re.IGNORECASE)
# The community or the v3 user goes, and a marker a pass already wrote is
# taken whole, so a second pass leaves the line as it is (bug 4).
_ASA_SNMP_SECRET = re.compile(
    rf"(?P<keep>\b(?:community(?:\s+[08](?=\s+\S))?|version\s+3))\s+(?:{re.escape(REDACTION_MARKER)}|\S+)", re.IGNORECASE
)
_SNMP_HOST_WORDS = frozenset({"traps", "informs", "version", "vrf", "use-vrf", "source-interface", "udp-port"})

# A description is free text an operator wrote, not a statement with a value:
# `description Key Account uplink` names a customer, and the keyword rules
# above read its `Key` as a key and cut the rest. So is the column of the
# description tables, whose rows start with the interface they describe.
# Neither carries a credential the device uses, but an operator may have
# typed one into it (`description guest wifi password Welcome1`), so what
# follows `password`, `passwd`, `secret` or `community` there still goes.
# `pwd` and `psk` are such words, and `pass` given a value (`pass: X`); `pw`
# is not, since a pseudowire's description says `PW to PE2`, nor is `key`:
# it is the word that cut `Key Account`. The cost is accepted that harmless
# words after one of them go too, as in `secret shared with NOC`. A URL's credentials go as well, because that pass runs
# first. A row ends the table when it is not an interface's, so the
# configuration after it in a transcript is read as configuration.
_DESCRIPTION_LINE = re.compile(r"^\s*(?:neighbor\s+\S+\s+|port\s+|system\s+)?description\b", re.IGNORECASE)
_DESCRIPTION_SECRET = re.compile(
    r"^(?P<keep>.*?\b(?:password|passwd|pwd|psk|secret|community|pass(?=\s*[:=])))\b(?P<value>\W*\w.*)$",
    re.IGNORECASE,
)
_DESCRIPTION_TABLE = re.compile(r"^\s*(?:interface|port)\s.*\bdescription\s*$", re.IGNORECASE)
_TABLE_RULE = re.compile(r"^\s*-+\s*$")
# A banner is free text too, and read by the same rule (owner decision D3):
# `Key personnel only` is no key. The line that opens one is its text, and
# the ASA writes each line of a banner as such a line. IOS, IOS-XR and NX-OS
# run the text on over the lines up to the closing delimiter, but only where
# the opening line ends on it (`banner motd ^C`, `banner motd #`) and the
# delimiter comes back: an ASA line opening its text with `(` or `-` is no
# delimiter, and a later line ending in the same character would otherwise
# turn the configuration between them into text that keeps a `key-string`.
# IOS's `^C` is never typed as text, so its text may begin on the opening line.
# Junos says its banner in `system login { message "..."; }`, and the
# announcement shown after login beside it.
_BANNER_LINE = re.compile(r"^\s*banner\s+[\w-]+\s", re.IGNORECASE)
_JUNOS_LOGIN_TEXT = re.compile(r'^\s*(?:message|announcement)\s+"', re.IGNORECASE)


def _banner_text_end(lines: list[str], start: int) -> int:
    """The index of the last line of banner text opened at `start`, which is `start` itself where it runs on to no other."""
    opened = _BANNER.match(lines[start].strip())
    if not opened or (opened.group("delimiter") != "^C" and opened.group("rest").strip()):
        return start
    end = _banner_end(lines, start)
    return start if end is None else end


def _asa_bare_snmp_host(line: str, nameifs: set[str]) -> bool:
    """Is this an ASA host line that takes the global community, so carries no secret?"""
    bare = _ASA_SNMP_BARE_HOST.match(line)
    if not bare or bare.group("nameif").lower() not in nameifs:
        return False
    try:
        ipaddress.ip_address(bare.group("address"))
    except ValueError:
        return False
    return True


def _ntp_key_number(line: str, match: re.Match, parent: str, blocks: list[str]) -> bool:
    """Is the secret this line seems to carry the key number of an NTP association, or a trusted key's?"""
    under_ntp = parent.lower() == "ntp" or "ntp" in blocks
    trusted = _NTP_TRUSTED_KEY.match(line)
    if trusted:
        return bool(trusted.group("ntp") or under_ntp)
    association = _NTP_ASSOCIATION.match(line)
    if not association or not (association.group("ntp") or under_ntp):
        return False
    keyword = match.group("keep").split()[-1].lower()
    return keyword == "key" and bool(_NTP_KEY_NUMBER.match(match.group("value")))


def redact(text: str, *, automated: bool = False) -> tuple[str, int]:
    """Strip credential material from raw device output.

    Returns the redacted text and the number of lines changed. Applied at
    collection time, before anything is written to disk, so no snapshot ever
    contains a password, key or SNMP community string.

    The text is cleaned of control characters first (see :func:`clean_text`):
    an escape or a NUL in front of `snmp-server community X` kept every rule
    anchored at the line's start from reading it, and the reader, which
    cleans what it reads, then had the community in clear. What is cleaned
    away is not counted as changed.

    ``automated`` is a command an automation types, read on its own: it has
    no indentation, and what needs one to be judged is cut (see
    _A_SETTING_LINE).
    """
    text = clean_text(text or "")
    out: list[str] = []
    blocks: list[str] = []   # the Junos braces open at this line, outermost first
    parent = ""              # the unindented line this one sits under
    described = False        # inside a table whose last column is the description
    banner = -1              # the index of the last line of the banner text open here
    answering = False        # the EEM action before this one waits for a password prompt
    macro = False            # inside an IOS macro's body, which runs to its `@`
    lines = (text or "").splitlines()
    # The ASA names its interfaces before its SNMP hosts, but a host line is
    # judged on every name the output gives, wherever it stands.
    nameifs = {named.group("nameif").lower() for named in map(_ASA_NAMEIF.match, lines) if named}
    for index, line in enumerate(lines):
        if macro and line.strip() == "@":
            macro = False
        elif _MACRO_NAME.match(line):
            macro = True
        if line.strip() and not line[0].isspace():
            parent = line.strip()
            answering = False
        if index > banner and _BANNER_LINE.match(line):
            banner = _banner_text_end(lines, index)
        free_text = index <= banner or (blocks[-1:] == ["login"] and _JUNOS_LOGIN_TEXT.match(line))
        # A URL's credentials first: they sit in the middle of a line no
        # keyword rule reads, and the rest of the line is worth keeping.
        line = _URL_USERINFO.sub(f"://{REDACTION_MARKER}@", line)
        line = _MAIL_SERVER.sub(rf"\g<head>{REDACTION_MARKER}\g<tail>", line)
        words = line.split()
        row = bool(words) and is_interface_name(words[0])
        if _DESCRIPTION_TABLE.match(line):
            described = True
        elif described and not row and not _TABLE_RULE.match(line):
            described = False
        match = _JUNOS_SECRET_DATA.match(line)
        secret_data = match
        if not match and (_DESCRIPTION_LINE.match(line) or (described and row) or free_text):
            said = _DESCRIPTION_SECRET.match(line)
            if said:
                out.append(f"{said.group('keep')} {REDACTION_MARKER}")
            else:
                out.append(line)
            continue
        if not match:
            variable = _EEM_ENVIRONMENT.match(line)
            if variable:
                out.append(f"{variable.group('keep')} {REDACTION_MARKER}")
                continue
            action = (
                _EEM_CLI.match(line)
                or _EEM_BARE_CLI.match(line)
                or (_JUNOS_COMMAND.match(line) if blocks[-1:] == ["commands"] else _JUNOS_SET_COMMAND.match(line))
            )
            if action:
                typed = action.group("command")
                command = REDACTION_MARKER if answering and typed.strip() else redact(typed, automated=True)[0]
                answering = _eem_asks_for_secret(typed, action.group("tail"))
                out.append(f"{action.group('head')}{command}{action.group('tail')}")
                continue
            isakmp = _ISAKMP_KEY.match(line)
            if isakmp:
                out.append(f"{isakmp.group('keep')} {REDACTION_MARKER}{isakmp.group('rest')}")
                continue
            keyring = _KEYRING_PSK.match(line)
            if keyring:
                out.append(f"{keyring.group('keep')} {REDACTION_MARKER}")
                continue
            isis = _XR_ISIS_PASSWORD.match(line)
            if isis:
                out.append(f"{isis.group('keep')} {REDACTION_MARKER}{isis.group('rest')}")
                continue
            if _asa_bare_snmp_host(line, nameifs):
                out.append(line)
                continue
            asa = _ASA_SNMP_HOST.match(line)
            if asa:
                rest = _ASA_SNMP_SECRET.sub(rf"\g<keep> {REDACTION_MARKER}", asa.group("rest"))
                out.append(asa.group("head") + rest)
                continue
            match = _secret_line(line)
            if match and (
                (_KEY_ID_LINE.match(line) and _KEY_CHAIN.match(parent))
                or (_JUNOS_KEY_ID_LINE.match(line) and blocks[-1:] == ["key-chain"])
                or _ntp_key_number(line, match, parent, blocks)
                or _A_MODE_LINE.match(line)
                or (_A_SETTING_LINE.match(line) and not automated and not macro)
                or _SSH_ALGORITHM_LINE.match(line)
                or (_JUNOS_SSH_ALGORITHM_LINE.match(line) and blocks[-1:] == ["ssh"])
                or _JUNOS_KEPT_SECRET_WORDS.match(line)
            ):
                match = None
            if not match:
                bare = _BARE_AUTHENTICATION.match(line)
                word = bare.group("word").lower() if bare else ""
                if bare and (word not in _AUTHENTICATION_MODES
                             or (word == "send-only" and not _ROUTER_ISIS.match(parent))):
                    match = bare
        # An SNMP community is the secret where it stands, though a keyword
        # rule matched the line too: a community such as `RT-KEY`, `my-secret`
        # or `ops-md5` ends in a keyword, and the keyword rule, cutting after
        # it, kept the community whole. Whichever rule redacts from further
        # left is the one that holds.
        if _SNMP_WORD.search(line) or "snmp" in blocks:
            community = COMMUNITY_LINE.match(line)
            if community and (not match or community.end("keep") < match.end("keep")):
                match = community
        host = SNMP_HOST_LINE.match(line)
        if host and (
            (not host.group("prefix") and not _SNMP_HOST_SAID.search(host.group("keep"))
             and not _SNMP_VRF.match(parent))
            # The value has to be non-empty, so a line that ends on a keyword
            # pair (`use-vrf management`) would otherwise give that pair up
            # as the "secret". A value that starts with a keyword is not one.
            or host.group("value").split()[0].lower() in _SNMP_HOST_WORDS
        ):
            host = None
        if host and (not match or host.end("keep") < match.end("keep")):
            match = host
        value = match.group("value").strip() if match else ""
        # A Junos stanza opens with the secret on the same line as its brace:
        # `community public {`. The brace is structure, not secret, and stays
        # so the block under it still closes where it did, a `## Warning`
        # after it or not.
        suffix = ""
        annotated = False
        structure = _JUNOS_ANNOTATION.sub("", value)
        if structure.endswith("{"):
            # A block named with a keyword at its end, `NTP-SECRET {`, has the
            # brace alone after the keyword, and the line is kept. An
            # annotation after that brace is no structure: `NTP-SECRET { ##
            # password X` kept the X. The name and the brace stay and the
            # annotation goes, as it goes after `community public {`.
            annotated = structure != value
            value, suffix = structure[:-1].strip(), " {"
        elif match and blocks:
            # A Junos leaf ends in `;`, and cut with its value it was no leaf
            # any more (BUG-COLLECTOR-JUNOS-REDACT-SEMICOLON). The `;` stays,
            # with the braces that close on the same line; the value before
            # it goes as before, and so does the `## SECRET-DATA` Junos
            # prints after a secret (it never reaches disk). Only inside a Junos block, and only where the
            # value is Junos words, quoted or not, none with a `;` in it: on
            # any other line the `;` may be part of the secret, and the whole
            # value goes.
            leaf = _JUNOS_LEAF_END.match(value)
            if leaf:
                value, suffix = leaf.group("value"), leaf.group("end")
        quoted = _junos_secret_data(line, bool(blocks)) if match is not None and match is secret_data else None
        if quoted is not None:
            out.append(quoted)
        elif match and value:
            # From the line, not the match: a match made on the line with a
            # BGP name masked keeps the name as the line has it.
            out.append(f"{line[:match.end('keep')]} {REDACTION_MARKER}{suffix}")
        elif match and annotated:
            out.append(f"{line[:match.end('keep')]}{suffix}")
        else:
            out.append(line)
        # Track the braces on the original line, so `snmp {` is known to be
        # open when its `community public {` arrives and closed after it.
        structure = _JUNOS_ANNOTATION.sub("", line)
        opened = _JUNOS_BLOCK_OPEN.match(structure)
        if opened:
            blocks.append(opened.group("name").lower())
        elif structure.strip() == "}" and blocks:
            blocks.pop()
    # What changed is counted on the text, not on the rules that fired: a
    # rule that cuts a value a pass already cut writes the line it was given,
    # and a second pass over redacted text (an export, a re-run on a
    # snapshot) has changed nothing (bug 4). On raw output, where no value is
    # the marker yet, every rule that fires changes its line, so the count is
    # the one the rules gave.
    changed = sum(source != redacted for source, redacted in zip(lines, out))
    return "\n".join(out), changed


def slugify(command: str) -> str:
    """Filename-safe form of a show command."""
    return re.sub(r"[^a-z0-9]+", "_", command.lower()).strip("_")


def unique_slugs(commands: Iterable[str]) -> dict[str, str]:
    """A file stem per command, distinct even where the slugs collide.

    `show ptp foreign masters` and `show ptp foreign-masters` are two
    allowlisted spellings and one slug; whichever ran second overwrote the
    first, so an `% Invalid input` could replace a good answer. The second
    keeps its slug with a short hash of the command appended. The manifest
    records the paths, so nothing downstream reads a slug it did not write.
    """
    out: dict[str, str] = {}
    taken: set[str] = set()
    for command in commands:
        if command in out:
            continue
        stem = slugify(command)
        if stem in taken:
            stem = f"{stem}_{hashlib.sha1(command.encode('utf-8')).hexdigest()[:6]}"
        taken.add(stem)
        out[command] = stem
    return out


def jsonable(value: Any) -> Any:
    """Coerce Genie/pyATS structures into something json.dump can write."""
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class CommandResult:
    """Outcome of collecting one command from one device."""

    command: str
    status: str = "failed"  # parsed | empty | unparsed | raw | unsupported | failed
    state_file: str | None = None
    raw_file: str | None = None
    redacted_lines: int = 0
    seconds: float = 0.0
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "status": self.status,
            "state_file": self.state_file,
            "raw_file": self.raw_file,
            "redacted_lines": self.redacted_lines,
            "seconds": self.seconds,
            "detail": self.detail,
        }


@dataclass
class DeviceResult:
    """Outcome of collecting from one device."""

    name: str
    # The OS the device was collected as: what the testbed declared, unless
    # the login proved another one and the reconnect collected it under that.
    # Every reader downstream picks its parsers by this, so it has to name the
    # allowlist that was actually sent.
    os: str | None = None
    platform: str | None = None
    connected: bool = False
    error: str | None = None
    connect_log: str | None = None
    probed: bool = False
    # What the login prompt said the device runs, when it said anything. Kept
    # apart from `os`: on a device that was not collected, the two disagreeing
    # is the finding, and finalize acts on it.
    detected_os: str | None = None
    # What the testbed declared, where the reconnect collected the device as
    # something else. Finalize corrects the testbed from it.
    declared_os: str | None = None
    # The ssh_options the login needed, where the ssh client and the device
    # shared no algorithm until DiscoNet added what the device offered. Only
    # what got the client past the negotiation; finalize writes it into the
    # device's block so the next run does not negotiate twice.
    ssh_options: str | None = None
    # Which credential set the login was tried under — "1" for the testbed's
    # own, "2" and on for the ones `disconet retry` wrote — read from the
    # testbed text, never from the resolved credential. `retry` counts these
    # across the runs to stop at the cap.
    credential_set: str | None = None
    # The protocol the device was reached over where it is not the one the
    # testbed declares: telnet, after the ssh client refused the device's
    # host key and TCP/23 answered. Finalize writes it into the block.
    protocol: str | None = None
    # Set where OpenSSH refused the device's RSA host key for its length and
    # the login went through DiscoNet's own client (netstate.legacyssh):
    # the client's name, and the key's size where the pin says it. Reported,
    # because a host key that short proves little about who answered.
    ssh_client: str | None = None
    host_key_bits: int | None = None
    # VRFs whose per-VRF tables were not asked for, each with the reason:
    # past the limit, or named with a character no command is rendered with.
    vrfs_not_read: dict[str, str] = field(default_factory=dict)
    commands: list[CommandResult] = field(default_factory=list)

    @property
    def parsed_count(self) -> int:
        return sum(1 for c in self.commands if c.status == "parsed")

    def as_dict(self) -> dict[str, Any]:
        entry = {
            "name": self.name,
            "os": self.os,
            "platform": self.platform,
            "connected": self.connected,
            "error": self.error,
            "connect_log": self.connect_log,
            "probed": self.probed,
            "detected_os": self.detected_os,
            "commands": [c.as_dict() for c in self.commands],
        }
        # Only where it differs, so every other entry, and every manifest
        # written before the reconnect existed, reads exactly as it did.
        if self.declared_os and self.declared_os != self.os:
            entry["declared_os"] = self.declared_os
        if self.ssh_options:
            entry["ssh_options"] = self.ssh_options
        if self.credential_set:
            entry["credential_set"] = self.credential_set
        if self.protocol:
            entry["protocol"] = self.protocol
        if self.ssh_client:
            entry["ssh_client"] = self.ssh_client
        if self.host_key_bits:
            entry["host_key_bits"] = self.host_key_bits
        if self.vrfs_not_read:
            entry["vrfs_not_read"] = dict(self.vrfs_not_read)
        return entry


# --------------------------------------------------------------------------
# Device interaction
# --------------------------------------------------------------------------


def _write_json(path: Path, payload: Any) -> None:
    """Write the whole file or none of it.

    Written beside the target and renamed over it, so a run cut off mid-write
    leaves the previous file, never half of the new one that nothing can read.
    """
    partial = path.with_name(path.name + ".tmp")
    # Owner-only, directory and file: a snapshot describes a customer's network.
    with private.open_text(partial) as handle:
        json.dump(jsonable(payload), handle, indent=2, sort_keys=True)
        handle.write("\n")
    partial.replace(path)


def _write_raw(path: Path, text: str) -> tuple[str, int]:
    """Redact, then write. Nothing reaches disk unredacted; the redacted text is what the parser gets too."""
    redacted, changed = redact(text)
    private.write_text(path, redacted + "\n")
    return redacted, changed


def _execute(device, policy: CommandPolicy, os_name: str, command: str, timeout: int) -> str:
    """Execute one allowlisted show command and return its raw output.

    The only place in DiscoNet where a command reaches a device.
    """
    policy.assert_allowed(os_name, command)
    return device.execute(command, timeout=timeout)


# A device that answers "% Invalid input detected" does not have the command:
# IOS-XRv 9000 has no `show inventory`. That is a fact about the platform, not
# a collection failure, and reporting it as one buries the real failures.
UNSUPPORTED_MARKERS = (
    "invalid input detected",
    "invalid command",
    "incomplete command",
    "unknown command",
)

TIMEOUT_MARKERS = ("timeout occurred", "timeout value:")

# A device's whole answer that the protocol a command shows is not running:
# IOS and IOS-XE `% BGP not active`, IOS-XR `% BGP instance 'default' not
# active`, Junos `BGP is not running`. See Snapshot.answered_not_running.
_NOT_RUNNING_ANSWER = re.compile(
    r"^(?:% ?BGP not active|% ?BGP instance '[^']*' not active|BGP is not running)\.?$", re.IGNORECASE,
)
# IOS-XR prints the time before every command's output.
_XR_TIME_STAMP = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\S+)?$",
)


def says_not_running(text: str) -> bool:
    """Is this whole answer a device saying the protocol the command shows is not running?

    Only a whole answer of that kind counts, the IOS-XR time stamp aside, so
    output that prints anything after such a line is not mistaken for one.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    lines = [line for line in lines if not _XR_TIME_STAMP.match(line)]
    return bool(lines) and all(_NOT_RUNNING_ANSWER.match(line) for line in lines)

# Every device of an OS has its configuration command and `show version`, so
# one that calls either invalid input is not lacking it: the session is not
# privileged enough to be shown it (`show running-config` at privilege 1).
# Called 'unsupported', it became a platform gap, the one thing it is not.
PRIVILEGE_REFUSAL_DETAIL = (
    "refused as invalid input, though every device of this OS has the command, "
    "which is what an unprivileged session looks like — check the login's "
    "privilege level, and if this device needs a second 'enable' after login, "
    f"set custom: {{{DOUBLE_ENABLE_KEY}: true}} on it"
)


def summarise_error(exc: BaseException, limit: int = 160) -> str:
    """One scannable line out of a unicon traceback.

    unicon raises with the entire dialog embedded — the command, the buffer and
    the full list of regex patterns it was waiting on. Rendered verbatim into a
    gap list that is several hundred characters of escaped regex per entry, so
    the whitespace is collapsed and the tail dropped. The complete text stays
    in `collect.log`.
    """
    text = " ".join(f"{type(exc).__name__}: {exc}".split())
    return text[:limit].rstrip() + ("…" if len(text) > limit else "")


def is_timeout(exc: BaseException) -> bool:
    """Did the device simply not finish answering?"""
    message = str(exc).lower()
    return "timeout" in type(exc).__name__.lower() or any(
        marker in message for marker in TIMEOUT_MARKERS
    )


def describe_failure(exc: BaseException, timeout: int, everywhere: bool = False) -> tuple[str, str]:
    """Classify a failed execution as (status, one-line detail).

    ``everywhere`` says the command is one no device of its OS lacks, so a
    refusal of it is about privilege rather than the platform.
    """
    message = str(exc).lower()
    if any(marker in message for marker in UNSUPPORTED_MARKERS):
        if everywhere:
            return "failed", PRIVILEGE_REFUSAL_DETAIL
        return "unsupported", "the platform rejected the command as invalid input"
    if is_timeout(exc):
        return "failed", f"no prompt within {timeout}s — the device did not finish answering"
    return "failed", summarise_error(exc)


def _every_device_has(os_name: str, command: str) -> bool:
    """Is this the OS's configuration command or `show version`, which no device of it lacks?"""
    platform = platforms.platform_for(os_name)
    everywhere = (IDENTIFY_COMMAND, platform.config_command if platform else "")
    return CommandPolicy.normalise(command) in {CommandPolicy.normalise(c) for c in everywhere if c}


def _collect_command(
    device,
    os_name: str,
    command: str,
    policy: CommandPolicy,
    snapshot_root: Path,
    device_name: str,
    parse: bool,
    command_timeout: int,
    reopen_session: Callable[[], bool] | None = None,
    slug: str | None = None,
    answer: str | None = None,
) -> CommandResult:
    """Collect one command. Paths recorded are relative to ``snapshot_root``.

    ``answer`` is what this session already said to the command, asked to
    identify the device; it is kept as the command's sample, not asked again.
    """
    device_dir = snapshot_root / device_name
    if not device_dir.resolve().is_relative_to(snapshot_root.resolve()) or device_dir.resolve() == snapshot_root.resolve():
        raise CollectionError(f"refusing to write outside the snapshot for a device named {device_name!r}")
    result = CommandResult(command=command)
    stem = slug or slugify(command)
    started = datetime.now(timezone.utc)

    raw = answer
    attempts = TIMEOUT_ATTEMPTS if answer is None else 0
    for attempt in range(1, attempts + 1):
        try:
            raw = _execute(device, policy, os_name, command, command_timeout)
            break
        except CommandNotAllowed:
            raise
        except Exception as exc:  # noqa: BLE001 - a dead command is not fatal
            status, detail = describe_failure(exc, command_timeout, _every_device_has(os_name, command))
            timed_out = status == "failed" and is_timeout(exc)
            # Virtual routers drop the occasional first answer — a burst of
            # console logging while the session is still settling is enough.
            # One retry of the same allowlisted show command costs seconds and
            # recovers it; a device that is genuinely wedged still fails.
            if timed_out and attempt < TIMEOUT_ATTEMPTS:
                log.warning(
                    "%s: %s timed out after %ds, retrying once",
                    device_name, command, command_timeout,
                )
                time.sleep(RETRY_PAUSE)
                # A fresh session, so the retry cannot read the tail of the
                # answer that timed out. If it cannot be reopened, the original
                # failure stands rather than a guess at half an answer.
                if reopen_session is None or reopen_session():
                    continue
                detail = f"{detail}; reconnecting for a retry failed"
            elif timed_out and reopen_session is not None and not reopen_session():
                # The last attempt gave up, but its answer is still arriving:
                # the next command would read that tail as its own output.
                detail = f"{detail}; reconnecting after it failed"
            result.status = status
            result.detail = detail
            log.warning("%s: %s %s: %s", device_name, command, status, detail)
            result.seconds = round((datetime.now(timezone.utc) - started).total_seconds(), 2)
            return result

    raw_path = device_dir / "raw" / f"{stem}.txt"
    # The parser reads the redacted text, not the original: a secret in a
    # free-text field a parser keeps (a description, a banner) would
    # otherwise land in the state file and the database in clear.
    raw, result.redacted_lines = _write_raw(raw_path, raw or "")
    result.raw_file = str(raw_path.relative_to(snapshot_root))

    if not parse:
        result.status = "raw"
        log.info(
            "%s: %s -> raw (%d line(s) redacted)", device_name, command, result.redacted_lines
        )
        result.seconds = round((datetime.now(timezone.utc) - started).total_seconds(), 2)
        return result

    try:
        # Parse the output already captured rather than letting Genie re-run the
        # command: the device is touched once, and the raw file and the
        # structured state describe the same sample.
        parsed = device.parse(command, output=raw)
    except Exception as exc:  # noqa: BLE001 - no parser is an expected case
        # Classified by exception class name rather than by importing the Genie
        # classes, so this module stays importable — and testable — without
        # pyATS present. SchemaEmptyParserError means the command ran and had
        # nothing to report (no neighbours), which is itself a fact worth
        # recording; anything else means no usable parser.
        parsed = None
        result.status = "empty" if type(exc).__name__ == "SchemaEmptyParserError" else "unparsed"
        result.detail = f"{type(exc).__name__}: {exc}".splitlines()[0][:400]
        if result.status == "unparsed":
            log.warning(
                "%s: %s -> unparsed (no Genie parser), raw text kept", device_name, command
            )
        else:
            log.info("%s: %s -> empty", device_name, command)
    else:
        if parsed:
            result.status = "parsed"
            log.info("%s: %s -> parsed", device_name, command)
        else:
            result.status = "empty"
            result.detail = "parser returned no data"
            log.info("%s: %s -> empty", device_name, command)

    if parsed or result.status == "empty":
        state_path = device_dir / "state" / f"{stem}.json"
        _write_json(state_path, parsed or {})
        result.state_file = str(state_path.relative_to(snapshot_root))

    result.seconds = round((datetime.now(timezone.utc) - started).total_seconds(), 2)
    return result


# --------------------------------------------------------------------------
# Reachability probes (opt-in)
# --------------------------------------------------------------------------

# Where a learned neighbour address sits in the parsed ARP / ND structures.
# IOS-XE returns 'interface' for IPv6 neighbours where IOS-XR returns
# 'interfaces', so both spellings are accepted.
NEIGHBOUR_TABLE_COMMANDS = (
    "show ip arp",
    "show arp detail",
    "show ipv6 neighbors",
)


def neighbour_tables(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """The per-interface tables of a parsed ARP or neighbour table, in either layout.

    Cisco's parsers nest them under `interfaces` (or `interface`). ASA's keys
    the table by nameif at the top level, each name holding an `ipv4` block
    of neighbours whose shape is the Cisco one. The probes and the topology
    read the same tables, so they read them through this one rule.
    """
    tables = [parsed[key] for key in ("interfaces", "interface") if isinstance(parsed.get(key), dict)]
    if not tables and parsed and all(
        isinstance(value, dict) and isinstance(value.get("ipv4"), dict) for value in parsed.values()
    ):
        tables = [parsed]
    return tables


def neighbour_addresses(
    parsed: dict[str, Any] | None, interfaces: Iterable[str] | None = None
) -> list[str]:
    """Addresses a device has actually learned on a connected interface.

    Only dynamically learned entries are returned: a static entry describes the
    device's own address, which is pointless to probe. A link-local neighbour
    is left out too: it is reached only through a named interface, which
    `ping <address>` does not give, so IOS-XE stops to ask for one and the
    probe times out against a neighbour that is there. Multicast, loopback and
    unspecified addresses are no neighbour at all. The result is sorted, so a
    run always probes the same targets in the same order.

    Given `interfaces`, only the neighbours learned on those interfaces are
    returned, the names compared in their full spelling.
    """
    found: set[str] = set()
    if not isinstance(parsed, dict):
        return []
    wanted = None if interfaces is None else {normalise_interface(name) for name in interfaces}

    for table in neighbour_tables(parsed):
        for name, entry in table.items():
            if not isinstance(entry, dict):
                continue
            if wanted is not None and normalise_interface(str(name)) not in wanted:
                continue
            # IOS-XE ARP nests neighbours under 'ipv4'; ND puts them at the top.
            candidates = [entry.get("neighbors")]
            family = entry.get("ipv4")
            if isinstance(family, dict):
                candidates.append(family.get("neighbors"))
            for neighbours in candidates:
                if not isinstance(neighbours, dict):
                    continue
                for address, detail in neighbours.items():
                    detail = detail if isinstance(detail, dict) else {}
                    origin = str(detail.get("origin", "dynamic")).lower()
                    if origin and origin != "dynamic":
                        continue
                    try:
                        parsed_address = ipaddress.ip_address(str(detail.get("ip") or address).strip())
                    except ValueError:
                        continue
                    if (
                        parsed_address.is_link_local or parsed_address.is_multicast
                        or parsed_address.is_loopback or parsed_address.is_unspecified
                    ):
                        continue
                    found.add(str(detail.get("ip") or address).strip())
    return sorted(found, key=lambda value: ipaddress.ip_address(value).packed)


def _read_state(snapshot_root: Path, result: CommandResult | None) -> Any:
    """The parsed state a collected command wrote, or None where there is none to read."""
    if not result or not result.state_file:
        return None
    path = snapshot_root / result.state_file
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _default_vrf_interfaces(
    snapshot_root: Path, by_command: Mapping[str, CommandResult], platform: Any
) -> set[str]:
    """The interfaces this device's own interface tables place in the default VRF.

    An interface no table names, or names without a VRF, is left out: its
    VRF is unknown, and unknown is not the default.
    """
    found: set[str] = set()
    families = platform.address_commands if platform else {}
    for family in ("ipv4", "ipv6"):
        for command in families.get(family, ()):
            parsed = _read_state(snapshot_root, by_command.get(CommandPolicy.normalise(command)))
            for name, detail in (parsed.items() if isinstance(parsed, dict) else ()):
                if isinstance(detail, dict) and str(detail.get("vrf") or "").strip().lower() in ("default", "global"):
                    found.add(str(name))
    return found


def _probe_device(
    device,
    os_name: str,
    policy: CommandPolicy,
    snapshot_root: Path,
    device_name: str,
    collected: list[CommandResult],
    probe_limit: int,
    probe_timeout: int,
    reopen_session: Callable[[], bool] | None = None,
) -> list[CommandResult]:
    """Ping the neighbour addresses this device has learned.

    Targets come from the device's own ARP and IPv6 neighbour tables, which
    were parsed moments ago in this same session, so the probe set is bounded
    by what the network already told us. A ping that times out is followed by
    a fresh session, as in :func:`_collect_command`; where none can be opened,
    probing stops, and the neighbours not pinged stay not probed.
    """
    device_dir = snapshot_root / device_name
    by_command = {CommandPolicy.normalise(c.command): c for c in collected}

    targets: list[str] = []
    platform = platforms.platform_for(os_name)
    commands = tuple(
        c for c in ((platform.arp_command, platform.nd_command) if platform else ()) if c
    ) + NEIGHBOUR_TABLE_COMMANDS
    # `ping <address>` runs in the default VRF. A table read with `vrf all`
    # (NX-OS) lists every VRF's neighbours with only the interface to tell
    # them apart, so from such a table the targets are the neighbours on an
    # interface this device's own interface tables place in the default VRF.
    # The rest stay not probed: a ping out of the wrong table reports a
    # neighbour that is there as unreachable.
    default_vrf = _default_vrf_interfaces(snapshot_root, by_command, platform)
    outside = 0
    for command in dict.fromkeys(commands):
        parsed = _read_state(snapshot_root, by_command.get(CommandPolicy.normalise(command)))
        if parsed is None:
            continue
        found = neighbour_addresses(parsed)
        if " vrf all" in CommandPolicy.normalise(command):
            kept = neighbour_addresses(parsed, default_vrf)
            outside += len(found) - len(kept)
            found = kept
        for address in found:
            if address not in targets:
                targets.append(address)
    if outside:
        log.info(
            "%s: %d neighbour address(es) outside the default VRF, or on an interface of "
            "unknown VRF, not probed", device_name, outside,
        )

    if not targets:
        log.info("%s: no learned neighbour addresses to probe", device_name)
        return []

    if len(targets) > probe_limit:
        log.warning(
            "%s: %d learned neighbour address(es), probing the first %d",
            device_name, len(targets), probe_limit,
        )
        targets = targets[:probe_limit]

    results: list[CommandResult] = []
    # `ping 2001:db8::1` and `ping 2001:db8:1::` slug alike, and the second
    # would overwrite the first's files; each command gets a stem of its own.
    commands = [policy.render_probe(os_name, address) for address in targets]
    stems = unique_slugs(commands)
    for command in commands:
        result = CommandResult(command=command)
        started = datetime.now(timezone.utc)
        try:
            raw = device.execute(command, timeout=probe_timeout)
        except Exception as exc:  # noqa: BLE001 - a failed probe is a result
            result.detail = f"{type(exc).__name__}: {exc}".splitlines()[0][:400]
            log.warning("%s: %s failed: %s", device_name, command, result.detail)
            result.seconds = round((datetime.now(timezone.utc) - started).total_seconds(), 2)
            results.append(result)
            if is_timeout(exc) and reopen_session is not None and not reopen_session():
                log.warning("%s: probing stopped, the session could not be reopened", device_name)
                break
            continue

        raw_path = device_dir / "raw" / f"{stems[command]}.txt"
        _, result.redacted_lines = _write_raw(raw_path, raw or "")
        result.raw_file = str(raw_path.relative_to(snapshot_root))

        try:
            parsed = device.parse(command, output=raw)
        except Exception as exc:  # noqa: BLE001
            parsed = None
            result.status = "unparsed"
            result.detail = f"{type(exc).__name__}: {exc}".splitlines()[0][:400]
        else:
            result.status = "parsed" if parsed else "empty"

        if parsed or result.status == "empty":
            state_path = device_dir / "state" / f"{stems[command]}.json"
            _write_json(state_path, parsed or {})
            result.state_file = str(state_path.relative_to(snapshot_root))

        rate = (parsed or {}).get("ping", {}).get("statistics", {}).get("success_rate_percent")
        log.info(
            "%s: %s -> %s%s", device_name, command, result.status,
            f" ({rate}% success)" if rate is not None else "",
        )
        result.seconds = round((datetime.now(timezone.utc) - started).total_seconds(), 2)
        results.append(result)

    return results


# --------------------------------------------------------------------------
# Per-VRF tables
# --------------------------------------------------------------------------


def vrf_names_from_config(config: str, os_name: str) -> list[str]:
    """The VRFs a running configuration declares, in the order declared.

    Every one, whatever its name holds: which of them a command can be
    rendered for is settled where the commands are, so that the rest are
    recorded as not read rather than lost here.
    """
    platform = platforms.platform_for(os_name)
    pattern = platform.vrf_declaration if platform else None
    if pattern is None:
        return []
    found: list[str] = []
    for match in pattern.finditer(config or ""):
        name = match.group("name")
        if name not in found:
            found.append(name)
    return found


def _collected_vrf_names(
    snapshot_root: Path, os_name: str, collected: list[CommandResult]
) -> list[str]:
    """Every VRF this device's own output named: its configuration and, where collected, its VRF table."""
    platform = platforms.platform_for(os_name)
    config_command = platform.config_command if platform else "show running-config"
    by_command = {CommandPolicy.normalise(c.command): c for c in collected}
    names: list[str] = []
    config = by_command.get(CommandPolicy.normalise(config_command))
    if config and config.raw_file and (snapshot_root / config.raw_file).is_file():
        names.extend(vrf_names_from_config((snapshot_root / config.raw_file).read_text(encoding="utf-8"), os_name))
    for command in VRF_TABLE_COMMANDS:
        result = by_command.get(CommandPolicy.normalise(command))
        if not result or not result.state_file or not (snapshot_root / result.state_file).is_file():
            continue
        try:
            parsed = json.loads((snapshot_root / result.state_file).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for name in parsed if isinstance(parsed, dict) else ():
            if str(name).lower() != "default" and str(name) not in names:
                names.append(str(name))
    return names


def _collect_per_vrf(
    device,
    os_name: str,
    policy: CommandPolicy,
    snapshot_root: Path,
    device_name: str,
    collected: list[CommandResult],
    command_timeout: int,
    vrf_limit: int = DEFAULT_VRF_LIMIT,
    reopen_session: Callable[[], bool] | None = None,
    not_read: dict[str, str] | None = None,
) -> list[CommandResult]:
    """Read each VRF's own tables, for every VRF the device's own output named.

    The names come from the configuration and the VRF table that were
    written moments ago in this same session, so the set is bounded by what
    the device declared, and each command is rendered through the same
    fixed-template rule as a probe. A table that times out is followed by a
    fresh session, as in :func:`_collect_command`; where none can be opened,
    the tables not yet read are recorded as not sent. A VRF whose tables are
    not asked for at all, past the limit or by a name no command is rendered
    with, goes into ``not_read`` with the reason, for the manifest and the
    gap list.
    """
    plan = policy.plan_for(os_name)
    if not plan.per_vrf:
        return []
    declared = _collected_vrf_names(snapshot_root, os_name, collected)
    if not declared:
        log.info("%s: no VRFs declared, no per-VRF tables to read", device_name)
        return []
    # A name is never sent that the rendering would refuse, and is never
    # dropped either: its tables are as unread as those past the limit, and
    # the gap list says so for both.
    skipped = {name: VRF_NAME_REFUSED for name in declared if not VRF_NAME.fullmatch(name)}
    names = [name for name in declared if name not in skipped]
    if skipped:
        log.warning(
            "%s: %d VRF(s) named with characters no per-VRF command is rendered with, not read",
            device_name, len(skipped),
        )
    if len(names) > vrf_limit:
        log.warning("%s: %d VRF(s) declared, reading the first %d", device_name, len(names), vrf_limit)
        skipped.update({name: VRF_LIMIT_REACHED.format(limit=vrf_limit) for name in names[vrf_limit:]})
        names = names[:vrf_limit]
    if not_read is not None:
        not_read.update(skipped)

    device_dir = snapshot_root / device_name
    commands = [policy.render_per_vrf(os_name, template, name) for template in plan.per_vrf for name in names]
    slugs = unique_slugs(commands)
    results: list[CommandResult] = []
    for index, command in enumerate(commands):
        result = CommandResult(command=command)
        started = datetime.now(timezone.utc)
        try:
            raw = device.execute(command, timeout=command_timeout)
        except Exception as exc:  # noqa: BLE001 - one VRF's table failing is a result
            result.status, result.detail = describe_failure(exc, command_timeout)
            log.warning("%s: %s %s: %s", device_name, command, result.status, result.detail)
            result.seconds = round((datetime.now(timezone.utc) - started).total_seconds(), 2)
            results.append(result)
            if result.status == "failed" and is_timeout(exc) and reopen_session is not None and not reopen_session():
                results.extend(
                    CommandResult(command=rest, detail=NOT_SENT_DETAIL) for rest in commands[index + 1:]
                )
                break
            continue

        raw_path = device_dir / "raw" / f"{slugs[command]}.txt"
        raw, result.redacted_lines = _write_raw(raw_path, raw or "")
        result.raw_file = str(raw_path.relative_to(snapshot_root))
        try:
            parsed = device.parse(command, output=raw)
        except Exception as exc:  # noqa: BLE001 - no parser is an expected case
            parsed = None
            result.status = "empty" if type(exc).__name__ == "SchemaEmptyParserError" else "unparsed"
            result.detail = f"{type(exc).__name__}: {exc}".splitlines()[0][:400]
        else:
            result.status = "parsed" if parsed else "empty"
        if parsed or result.status == "empty":
            state_path = device_dir / "state" / f"{slugs[command]}.json"
            _write_json(state_path, parsed or {})
            result.state_file = str(state_path.relative_to(snapshot_root))
        log.info("%s: %s -> %s", device_name, command, result.status)
        result.seconds = round((datetime.now(timezone.utc) - started).total_seconds(), 2)
        results.append(result)
    return results


# --------------------------------------------------------------------------
# Login dialogs
# --------------------------------------------------------------------------

# Read from a testbed device's `custom:` block. A jumphost that asks a question
# before it hands over a shell is not a fault to be worked around in code: it
# is a property of that jumphost, so it is described in the testbed beside the
# device it belongs to.
LOGIN_PROMPTS_KEY = "login_prompts"

# A login response is typed before any device prompt exists, so CommandPolicy
# cannot see it. This is what stands in its place: one short line, and no
# configuration verb. Answering `Yes` to a banner is not a command; anything
# shaped like one is refused before the run starts.
MAX_LOGIN_RESPONSE = 60


class LoginPromptError(CollectionError):
    """A `custom.login_prompts` entry that cannot be used as written."""


@dataclass(frozen=True)
class LoginPrompt:
    """One question a login can ask, and the answer to give it."""

    pattern: str
    response: str
    source: str = ""  # the testbed device that declared it

    def describe(self) -> str:
        # The answer is told by its length alone. It is typed at a login, and
        # what a login is told can be a password or a one-time code, which
        # the run log would then keep.
        return f"{self.source}: {self.pattern} -> {len(self.response)}-character answer"


def _validate_login_response(response: Any, where: str) -> str:
    if not isinstance(response, str):
        raise LoginPromptError(f"{where}: 'response' must be a string")
    if "\n" in response or "\r" in response:
        raise LoginPromptError(f"{where}: 'response' must be a single line")
    # ^U or ^W at the far end erases the answer typed before it, and what
    # follows is typed as a command, so the answer is held to printable text.
    if not re.fullmatch(r"[ -~]*", response):
        raise LoginPromptError(
            f"{where}: 'response' must be printable ASCII; a control character is "
            f"a key the far end acts on, not part of an answer"
        )
    if len(response) > MAX_LOGIN_RESPONSE:
        raise LoginPromptError(
            f"{where}: 'response' is longer than {MAX_LOGIN_RESPONSE} characters. "
            f"A login answer is a word, not a command"
        )
    # Every word, not only the first: 'Yes write memory' typed where a shell
    # already listens is the second command. And every start of a verb, not
    # only the verb: a CLI expands 'wri' to 'write' and 'rel' to 'reload'. A
    # single letter is left alone, because every letter starts several
    # commands on every CLI DiscoNet reads and none expands it; that keeps
    # 'y' and 'I accept' usable.
    verbs = sorted(
        token
        for word in response.lower().split()
        if len(word) > 1
        for token in CONFIG_TOKENS
        if token.startswith(word)
    )
    if verbs:
        raise LoginPromptError(
            f"{where}: refusing to send {response!r} at a login prompt — "
            f"'{verbs[0]}' is a configuration verb and DiscoNet is read-only"
        )
    return response


def _declared_prompts(device) -> list[LoginPrompt]:
    """The login prompts one testbed device declares for itself."""
    custom = getattr(device, "custom", None) or {}
    raw = custom.get(LOGIN_PROMPTS_KEY) if hasattr(custom, "get") else None
    if raw is None:
        return []
    name = str(getattr(device, "name", "?"))
    if not isinstance(raw, (list, tuple)):
        raise LoginPromptError(
            f"{name}: custom.{LOGIN_PROMPTS_KEY} must be a list of "
            f"pattern/response entries"
        )
    prompts: list[LoginPrompt] = []
    for index, entry in enumerate(raw, start=1):
        where = f"{name}: custom.{LOGIN_PROMPTS_KEY}[{index}]"
        if not hasattr(entry, "get"):
            raise LoginPromptError(f"{where}: must be a mapping with 'pattern' and 'response'")
        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip():
            raise LoginPromptError(f"{where}: 'pattern' must be a non-empty string")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise LoginPromptError(f"{where}: 'pattern' is not a valid regex: {exc}") from exc
        response = _validate_login_response(entry.get("response"), where)
        prompts.append(LoginPrompt(pattern, response, name))
    return prompts


def _connection_proxies(device) -> list[Any]:
    """Raw `proxy:` entries from every connection this device defines."""
    connections = getattr(device, "connections", None)
    if not connections:
        return []
    try:
        values = list(connections.values())
    except AttributeError:
        return []
    found: list[Any] = []
    for connection in values:
        if hasattr(connection, "get"):
            proxy = connection.get("proxy")
        else:
            proxy = getattr(connection, "proxy", None)
        if not proxy:
            continue
        found.extend(proxy if isinstance(proxy, (list, tuple)) else [proxy])
    return found


def proxy_names(device) -> tuple[str, ...]:
    """Testbed devices this device is reached through, in the order given.

    A proxy is written either as a bare device name or as a mapping carrying a
    `device:` key beside the ssh command; both forms name a device in the same
    testbed, and that is the only part DiscoNet needs.
    """
    names: list[str] = []
    for entry in _connection_proxies(device):
        if hasattr(entry, "get"):
            name = entry.get("device")
        elif isinstance(entry, str):
            name = entry
        else:
            name = None
        if isinstance(name, str) and name and name not in names:
            names.append(name)
    return tuple(names)


def login_prompts(device, testbed=None) -> tuple[LoginPrompt, ...]:
    """Every dialog this device's login can meet, its jumphosts included.

    The question belongs to the jumphost, so that is where an engineer writes
    it down — but the session that meets it belongs to the router behind the
    jumphost. unicon opens one spawn for the whole chain and matches the
    connect dialog against all of it, so a prompt declared on the jumphost has
    to be handed to the router's connect call or nothing will ever answer it.
    """
    testbed = testbed if testbed is not None else getattr(device, "testbed", None)
    devices = getattr(testbed, "devices", None) or {}
    sources = [device]
    for name in proxy_names(device):
        proxy = devices.get(name) if hasattr(devices, "get") else None
        if proxy is None:
            log.warning(
                "%s: proxy device '%s' is not in the testbed; any login prompts "
                "it declares cannot be answered", getattr(device, "name", "?"), name,
            )
            continue
        sources.append(proxy)

    found: list[LoginPrompt] = []
    seen: set[tuple[str, str]] = set()
    for source in sources:
        for prompt in _declared_prompts(source):
            key = (prompt.pattern, prompt.response)
            if key in seen:
                continue
            seen.add(key)
            found.append(prompt)
    return tuple(found)


# The ssh client's own question about a key it has not seen, in OpenSSH's
# words old and new. unicon's connection dialog answers it "yes" in every
# plugin; a login DiscoNet opens answers it "no", first.
HOST_KEY_QUESTION = r"continue connecting \(yes/no(/\[fingerprint\])?\)\?"


def _refuse_unknown_host_key(spawn) -> None:
    spawn.sendline("no")


def login_dialog(prompts: Iterable[LoginPrompt]):
    """The unicon connect dialog for one login: the host-key refusal, then the declared prompts.

    Never None. unicon's own connection dialog answers the ssh client's
    "continue connecting (yes/no)?" with "yes", which trusts whatever key
    the device, or whatever is pretending to be it, presents. A connect
    dialog is matched ahead of unicon's, so the first statement here answers
    "no" and the ssh client stops with "Host key verification failed". That
    question is asked only where nothing pinned the key: a hop typed on a jump
    host, whose own known_hosts decides; a session spawned here is run with
    StrictHostKeyChecking=yes and is refused before any question
    (:mod:`netstate.hostkeys`).

    ``loop_continue`` keeps the dialog running after an answer, because the
    banner is not the end of the login — the device prompt still has to be
    reached — and ``continue_timer`` restarts the connect timeout, since a
    jumphost that stops to ask a question has not stalled.
    """
    prompts = tuple(prompts)
    from unicon.eal.dialogs import Dialog, Statement  # imported late: heavy dependency

    statements = [
        Statement(
            pattern=HOST_KEY_QUESTION,
            action=_refuse_unknown_host_key,
            loop_continue=True,
            continue_timer=False,
        )
    ]
    for prompt in prompts:
        def answer(spawn, response=prompt.response):  # bound now, not at call time
            spawn.sendline(response)

        statements.append(
            Statement(
                pattern=prompt.pattern,
                action=answer,
                loop_continue=True,
                continue_timer=True,
            )
        )
    return Dialog(statements)


# --------------------------------------------------------------------------
# The second enable
# --------------------------------------------------------------------------


def _plaintext(value: Any) -> str:
    """The literal behind a pyATS Secret, or "" if it will not give one up.

    A password written as ``%ENC{...}`` arrives as a SecretString whose
    ``str()`` is the encoded form, not the secret; ``.plaintext`` is the
    secret. A ``%ENV{...}`` password has already been resolved to an ordinary
    string.

    Both callers want the same thing and want "" for the same reason: the
    transcript redactor cannot scrub a masked repr, and the second enable must
    not type one at a device.
    """
    for attribute in ("plaintext", "value"):
        text = getattr(value, attribute, None)
        if isinstance(text, str) and text:
            return text
    text = str(value or "")
    # A masked repr is not the secret, and searching for it would scrub nothing.
    return "" if not text or set(text) <= {"*"} else text


def enable_secret(device) -> str:
    """The password to answer the second enable's prompt with.

    The ``enable`` credential first, then ``default``: on these devices the
    second enable takes the same secret as the login, so a testbed that
    declares only the default credential still works.
    """
    credentials = getattr(device, "credentials", None) or {}
    for name in ("enable", "default"):
        try:
            entry = credentials[name] or {}
            secret = _plaintext(entry.get("password"))
        except (KeyError, TypeError, AttributeError):
            continue
        if secret:
            return secret
    return ""


def login_username(device) -> str | None:
    """The username the testbed's default credential resolved to.

    None where the testbed declares no default credential at all — a hand
    written testbed may put the login on the connection — and "" where it
    declares one that resolved to nothing, which is what an unset
    `DISCONET_USERNAME` produces from `%ENV{DISCONET_USERNAME}`.
    """
    credentials = getattr(device, "credentials", None) or {}
    try:
        entry = credentials["default"]
    except (KeyError, TypeError):
        return None
    if not hasattr(entry, "get") or "username" not in entry:
        return None
    return _plaintext(entry.get("username")) or str(entry.get("username") or "").strip()


NO_USERNAME_HINT = (
    "the testbed's default credential has no username: %ENV{{{env}}} resolved to "
    "nothing. Set {env} in .env beside the code, or in the estate's own .env "
    "(estates/<name>/.env); a fresh clone has neither until you copy them in"
)


def wants_double_enable(device) -> bool:
    """Does this device need a second enable after login?

    Read from ``custom: {double_enable: true}`` on the device, falling back to
    the same key on the testbed so a whole lab can be declared once. A device
    that sets it explicitly wins over the testbed, either way round.
    """
    for holder in (device, getattr(device, "testbed", None)):
        custom = getattr(holder, "custom", None) or {}
        value = custom.get(DOUBLE_ENABLE_KEY) if hasattr(custom, "get") else None
        if value is not None:
            return bool(value)
    return False


def _enable_dialog(password: str):
    """A one-statement dialog that answers the second enable's password prompt.

    unicon is imported here rather than at module scope so this module stays
    importable — and testable — without pyATS installed, the same way
    ``run_collect`` imports Genie.

    The secret is closed over by the handler rather than baked into the
    statement's pattern or action string, so it stays out of unicon's own
    logging of the dialog it is running.
    """
    from unicon.eal.dialogs import Dialog, Statement  # imported late: heavy dependency

    def answer(spawn):
        spawn.sendline(password)

    return Dialog(
        [
            Statement(
                pattern=ENABLE_PASSWORD_PROMPT,
                action=answer,
                loop_continue=True,
                continue_timer=False,
            )
        ]
    )


def _second_enable(device, timeout: int) -> None:
    """Send the second ``enable`` and answer the password prompt it raises.

    A device that does not ask for a password simply never triggers the
    dialog and lands back on the same prompt, so this is safe to leave set on
    a device that later stops needing it.

    Failures here are raised as :class:`SecondEnableError` rather than escaping
    as whatever unicon threw. The distinction is the whole diagnosis: it says
    the login worked and the privilege step did not, which is a different
    problem from a device that never answered the SSH port.
    """
    secret = enable_secret(device)
    if not secret:
        raise SecondEnableError(
            f"{DOUBLE_ENABLE_KEY} is set, but the testbed carries no enable or "
            f"default password to answer the prompt with"
        )
    log.info("%s: sending the second enable", device.name)
    try:
        device.execute(
            SECOND_ENABLE_COMMAND,
            reply=_enable_dialog(secret),
            timeout=timeout,
            # `enable` is a privilege transition, and unicon's execute service
            # objects to a command that moves the state machine unless it is
            # told to expect it. The prompt does not visibly change on these
            # devices, but the transition is real and unicon may see it.
            allow_state_change=True,
        )
    except Exception as exc:  # noqa: BLE001 - re-raised, classified
        raise SecondEnableError(
            f"the second enable failed: {summarise_error(exc, 300)}"
        ) from exc


# The command that identifies a device before it is privileged. Every
# platform's allowlist carries it, and every platform answers it from an
# unprivileged session; it is still checked against the allowlist for the
# declared OS before it is sent, like everything else.
IDENTIFY_COMMAND = "show version"


def identify_before_enable(
    device, os_name: str, policy: "CommandPolicy", timeout: int, transcript: str | Path | None = None,
    answered: dict[str, str] | None = None,
) -> str:
    """The OS a freshly opened, still unprivileged session proves, or "".

    The prompt first, because it costs nothing: `RP/0/RP0/CPU0:host#` is XR
    and nothing else prints it. Where the prompt proves nothing, `show
    version`, whose first lines name the software. A failure to ask is not a
    failure of the session: it returns "" and the enable goes ahead as it
    always did. ``transcript`` is where the connect was told to write its
    dialog. ``answered``, where given, keeps what `show version` said, by
    command, for the collection to keep rather than ask again.
    """
    proven = detect_os(connect_dialog_tail(_unicon_log_path(device, transcript)))
    if proven:
        return proven
    try:
        command = policy.assert_allowed(os_name, IDENTIFY_COMMAND)
    except (CommandNotAllowed, CollectionError):
        return ""
    try:
        output = device.execute(command, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - the enable decides the session
        log.debug("%s: %s before enable failed: %s", device.name, command, exc)
        return ""
    # An answer that said nothing proved nothing, and kept as the sample it
    # would stand in for one the collection could still get.
    if answered is not None and str(output or "").strip():
        answered[command] = str(output)
    proven = detect_os(str(output or ""))
    if proven:
        log.info(
            "%s: %s before enable names %s", device.name, command,
            platforms.label_for(proven, proven),
        )
    return proven


def _warn_about_overridden_arguments(device) -> None:
    """Say so when a testbed sets connection arguments this tool overrides.

    Writing the second enable into ``init_exec_commands`` is the obvious thing
    to try and it cannot work: the explicit keyword DiscoNet passes to
    ``connect()`` beats the testbed's ``arguments:`` block, so the list is
    discarded before it reaches unicon. Discarding it quietly leaves a testbed
    that looks correct, does nothing, and explains nothing.
    """
    connections = getattr(device, "connections", None) or {}
    items = connections.items() if hasattr(connections, "items") else ()
    for name, connection in items:
        arguments = connection.get("arguments") if hasattr(connection, "get") else None
        if not hasattr(arguments, "get"):
            continue
        for key in OVERRIDDEN_CONNECTION_ARGUMENTS:
            if arguments.get(key) is None:
                continue
            log.warning(
                "%s: connections.%s.arguments.%s is ignored — DiscoNet sets the "
                "session's init commands itself. A device that needs a second "
                "'enable' after login wants custom: {%s: true} instead.",
                device.name, name, key, DOUBLE_ENABLE_KEY,
            )


# A connect that died on a session setup command rather than on the network or
# the credentials. unicon embeds the buffer in the exception, so the device's
# own refusal is in the text even though the exception class says nothing.
PRIVILEGE_MARKERS = (
    "authorization failed",
    "invalid input detected",
    "invalid autocommand",
    "permission denied",
)

# The ssh client refusing the credentials, in its own words. It carries the
# words "permission denied" too, and is the opposite of a privilege problem.
AUTH_REFUSAL_MARKERS = (
    "permission denied, please try again",
    "permission denied (",
)

# The SSH client and the device never agreed on an algorithm, so nothing was
# ever typed. This splits a fleet cleanly down the middle — an older IOS-XE
# image offers only legacy crypto while a current IOS-XR box negotiates fine —
# and looks like "some devices are unreachable" rather than a crypto mismatch.
SSH_NEGOTIATION_MARKERS = (
    "unable to negotiate",
    "no matching key exchange method",
    "no matching host key type",
    "no matching cipher",
    "no matching mac",
    "no hostkey alg",
)

# The ssh client stopped to ask whether an unknown host key should be trusted.
# unicon answers the old "(yes/no)?" form of that question; OpenSSH 8.x asks
# "(yes/no/[fingerprint])?" instead, which older unicon patterns do not match,
# so the session sits at a prompt nobody will ever answer until it times out.
HOST_KEY_PROMPT_MARKERS = (
    "authenticity of host",
    "continue connecting",
    "host key verification failed",
)

# Different in kind: the key changed on a host already known. That is a
# rebuilt device, or it is worth knowing about, and waving it through is not a
# documentation tool's call to make.
HOST_KEY_CHANGED_MARKERS = (
    "remote host identification has changed",
    "possible dns spoofing",
)

# OpenSSH refusing a key that is not pinned, under StrictHostKeyChecking=yes:
# "No ED25519 host key is known for 10.0.0.1 and you have requested strict
# checking." Off port 22 the name is `[10.0.0.1]:2222`.
STRICT_REFUSAL_MARKER = "you have requested strict checking"
UNPINNED_ADDRESS = re.compile(r"host key is known for (?P<address>\S+) and you have requested", re.IGNORECASE)


def _address_and_port(name: str) -> tuple[str, int]:
    found = re.fullmatch(r"\[(?P<address>[^\]]+)\]:(?P<port>\d+)", name)
    return (found.group("address"), int(found.group("port"))) if found else (name, 22)


# What a login prompt says about the operating system behind it. IOS-XR is
# unmistakable — `RP/0/RP0/CPU0:hostname#` names the route processor in every
# prompt, and the sysadmin plane says `sysadmin-vm:`. A bare `hostname#` is
# IOS-XE, or NX-OS, or half a dozen other things, so it proves nothing and is
# not claimed. `show version`'s first line settles it when the dialog carries
# one, which the login check's dialog does.
#
# This exists because nothing else in the tool knows what a device runs. The
# testbed declares an `os:` and every plugin, allowlist and parser is chosen
# from that declaration; a wrong one fails in ways that look like a login
# problem — an IOS-XE plugin logs into an XR box, sends `enable`, and XR says
# `% Invalid input`. Read off the prompt, the mismatch is visible before a
# single command is sent, and it is the one failure the tool can fix itself.
# unicon's own lines in its log — "+++ Unicon plugin iosxe (unicon.plugins.iosxe)
# +++", the spawn command, the logfile path — every one of them stamped with
# this. They name the plugin the testbed chose, which is the guess being
# tested, and a detector that reads them proves the declaration with itself:
# every device under the IOS-XE plugin "proved" IOS-XE, so no banner was ever
# read and no `show version` ever asked.
UNICON_LOG_STAMP = "%UNICON-"

# Through a jump host the dialog is the whole chain in one transcript, and
# unicon names each hop before it is typed: "connection to jumphost", then
# "connection to <device>". The jump host's banner and prompt sit above the
# last of those lines; nothing printed after it came from anywhere but the
# jump host's ssh client and the device. A jump host's prompt can look like a
# device's — an EPNM shell prints `jump-02/netops#`, a root shell `root@jump#`
# — so a prompt is read only from the last hop. "connection to spawn: ssh ..."
# is the first spawn, not a hop, and is left out.
HOP_MARKER = re.compile(r"%UNICON-\w+:\s*connection to (?!spawn:)\S")

# What the jump host's ssh (or telnet) client prints as it gives up on the hop.
# The client then exits, and what follows is the jump host again: its prompt,
# back, which a root shell prints in the `user@host#` shape of a Junos login.
HOP_FAILURE_MARKERS = (
    "ssh: connect to host",
    "ssh: could not resolve hostname",
    "connection closed by",
    "connection reset by",
    "kex_exchange_identification",
    "unable to negotiate with",
    "host key verification failed",
    "permission denied (",
    "unable to connect to remote host",
)


def device_words(dialog: str) -> str:
    """What the device behind the last hop and its ssh client said.

    Lines above the last hop marker belong to a jump host; unicon's own log
    lines are taken out everywhere. Below it, a line that repeats the jump
    host's prompt is the jump host's, and nothing after the client's own
    failure is the device's: a hop that failed leaves only the jump host.
    """
    lines = (dialog or "").splitlines()
    last_hop = None
    for index, line in enumerate(lines):
        if HOP_MARKER.search(line):
            last_hop = index
    if last_hop is None:
        return "\n".join(line for line in lines if UNICON_LOG_STAMP not in line)
    # The jump host's prompt is the last thing it printed before the hop.
    above = [line.strip() for line in lines[:last_hop] if line.strip() and UNICON_LOG_STAMP not in line]
    jump_prompt = above[-1] if above else ""
    words: list[str] = []
    for line in lines[last_hop + 1:]:
        if UNICON_LOG_STAMP in line or (jump_prompt and line.strip() == jump_prompt):
            continue
        words.append(line)
        if any(phrase in line.lower() for phrase in HOP_FAILURE_MARKERS):
            break
    return "\n".join(words)


def detect_os(dialog: str) -> str:
    """The OS the login dialog proves, or "" when it proves nothing.

    The evidence — a prompt only one OS prints, a version banner naming it —
    is on each `Platform` in platforms.py; this is the one place the collector
    asks. Deliberately conservative: a wrong detection would send finalize to
    rewrite a correct testbed, which is worse than the guess it started with.
    Only the device's words are read; unicon's own lines name the plugin the
    testbed chose, which is the thing in question.
    """
    return platforms.detect(device_words(dialog))


def os_mismatch_hint(declared: str, detected: str, dialog: str) -> str:
    """The sentence that names a wrong `os:` and what to do about it.

    It names its evidence: the prompt where the prompt proved it, the banner
    where a version marker in the login dialog did, and `show version` where
    the dialog proved nothing and the device was asked.
    """
    platform = platforms.platform_for(detected)
    words = device_words(dialog)
    match = platform.prompt_match(words) if platform else None
    label = platforms.label_for(detected, detected)
    if match:
        proof = f"the login prompt is {label} ({match.group(0).strip()})"
    elif platform is not None and any(
        marker in words.lower() for marker in platform.version_markers
    ):
        proof = f"the login banner names {label}"
    else:
        proof = f"`{IDENTIFY_COMMAND}` names {label}"
    return (
        f"the testbed declares os: {declared}, but {proof}. Set os: {detected} "
        f"in the testbed — `disconet finalize` does it, and drops a double_enable "
        f"that does not belong on that platform"
    )


# The algorithms the device said it would accept, which is precisely the list
# the fix has to name. Not a secret: an SSH server offers it to anyone who
# connects, before any credential is sent.
OFFERED_ALGORITHMS = re.compile(r"their offer:\s*(?P<offer>[A-Za-z0-9@.,_+-]+)", re.IGNORECASE)


def _offered_algorithms(text: str) -> str:
    match = OFFERED_ALGORITHMS.search(text or "")
    return match.group("offer")[:300] if match else ""


# The refusals an ssh client makes before any credential is sent, each with
# the option that adds what the device offered and the `ssh -Q` query that
# lists what this client can add. The client stops at the first family it
# cannot agree on, so a device that is old on every count is corrected one
# family per login — and every one of those logins ends before a username is
# typed, which is what makes trying again straight away safe against a lockout.
LEGACY_SSH_FAMILIES = (
    ("no matching key exchange method", "KexAlgorithms", "kex", "key exchange"),
    ("no matching host key type", "HostKeyAlgorithms", "key", "host key type"),
    ("no matching cipher", "Ciphers", "cipher", "cipher"),
    ("no matching mac", "MACs", "mac", "MAC"),
)


# What the ssh client says to an option it does not know. Not a negotiation
# result: the option never reached the network, and the client is too old to
# take it.
UNKNOWN_SSH_OPTION_MARKERS = ("bad configuration option",)

# A refusal no option lifts. OpenSSH's sshkey_check_rsa_length rejects an RSA
# host key under SSH_RSA_MINIMUM_MODULUS_SIZE, 1024 bits, before it reads any
# option; RequiredRSASize only raises that floor. Old IOS generates 512 by
# default and the device never complains about it, so the collector logs in
# to such a device through DiscoNet's own client (netstate.legacyssh) rather
# than leave it out: see relay_connection.
SHORT_HOST_KEY_MARKERS = ("invalid key length",)


def is_short_host_key(transcript: str) -> bool:
    """Did OpenSSH refuse the device's RSA host key for its length?"""
    lowered = transcript.lower()
    return any(marker in lowered for marker in SHORT_HOST_KEY_MARKERS)


@dataclass
class RelayPlan:
    """The change that points a device's ssh connection at DiscoNet's own client."""

    connection: Any
    command: str
    bits: int | None
    saved: Any = None

    def apply(self) -> None:
        self.saved = self.connection.get("command")
        self.connection["command"] = self.command

    def undo(self) -> None:
        if self.saved is None:
            self.connection.pop("command", None)
        else:
            self.connection["command"] = self.saved


def relay_connection(device, known_hosts: Path | str | None) -> RelayPlan | str:
    """How to reach ``device`` through netstate.legacyssh, or why it cannot be.

    Only a session this machine's own ssh client opens: through a jump host,
    the client that refused is the jump host's, and nothing spawned here can
    stand in for it. The reason returned is added to the device's report.
    """
    connection = _cli_connection(device)
    if connection is None or not hasattr(connection, "get"):
        return "the device has no ssh connection DiscoNet's own client could take over"
    if str(connection.get("protocol") or "ssh").lower() != "ssh":
        return "the device's connection is not ssh"
    if proxy_names(device):
        return (
            "the refusal came from the jump host's ssh client, which DiscoNet cannot replace; "
            "a jump host with an older client, or a regenerated key on the device, is the way in"
        )
    if connection.get("command"):
        return "the connection is a literal `command:`, which DiscoNet does not rewrite"
    if not legacyssh.available():
        return (
            "DiscoNet's own ssh client needs asyncssh, which is not installed here "
            "(pip install asyncssh, or reinstall DiscoNet)"
        )
    address = _connection_ip(device)
    username = login_username(device)
    if not address or not username:
        return "the device has no address or username for DiscoNet's own ssh client"
    pins = Path(known_hosts) if known_hosts is not None else hostkeys.known_hosts_path("testbed.yaml")
    try:
        port = int(connection.get("port") or hostkeys.SSH_PORT)
    except (TypeError, ValueError):
        port = hostkeys.SSH_PORT
    bits = None
    for key_type, blob in hostkeys.known_keys(pins, address, port):
        bits = hostkeys.rsa_bits(key_type, blob) or bits
    return RelayPlan(connection, legacyssh.relay_command(address, port, username, pins), bits)


@dataclass(frozen=True)
class LegacySshFix:
    """What one negotiation refusal asks for, in the ssh client's own terms."""

    family: str                 # the `-Q` name: kex, key, cipher, mac
    label: str                  # the words for a log line
    offered: tuple[str, ...]    # what the device said it would accept
    option: str                 # `-o KexAlgorithms=+...`; "" when the client knows none of it
    unknown: tuple[str, ...]    # the offer this client cannot speak


def legacy_ssh_fix(dialog: str, known: Mapping[str, Sequence[str]] | None) -> LegacySshFix | None:
    """The option a refusal names, or None where the dialog holds no refusal.

    ``known`` is what this machine's client can add, by family, from
    :func:`client_algorithms`; None means nothing is filtered, which is right
    for a hop typed on a jump host whose client is not this one. Everything
    is added in the '+' form, so a device that negotiates normally keeps its
    modern algorithms and the weak ones are re-enabled for this device only.
    """
    lowered = (dialog or "").lower()
    for marker, option_name, family, label in LEGACY_SSH_FAMILIES:
        if marker not in lowered:
            continue
        offered = tuple(
            name for name in _offered_algorithms(dialog).split(",") if name.strip()
        )
        if not offered:
            return None
        accepted = offered
        if known is not None and family in known:
            speakable = {name.lower() for name in known[family]}
            accepted = tuple(name for name in offered if name.lower() in speakable)
        unknown = tuple(name for name in offered if name not in accepted)
        option = f"-o {option_name}=+{','.join(accepted)}" if accepted else ""
        return LegacySshFix(family, label, offered, option, unknown)
    return None


@functools.lru_cache(maxsize=1)
def _client_algorithms() -> dict[str, tuple[str, ...]] | None:
    found: dict[str, tuple[str, ...]] = {}
    for _marker, _option, family, _label in LEGACY_SSH_FAMILIES:
        try:
            listed = subprocess.run(
                ["ssh", "-Q", family], capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if listed.returncode != 0:
            return None
        found[family] = tuple(line.strip() for line in listed.stdout.splitlines() if line.strip())
    return found


def port_answers(address: str, port: int) -> bool:
    """Does a TCP listener answer here? The sweep's own probe, one address at a time."""
    answered, _banner = probe_address(address, port)
    return answered


def client_algorithms() -> dict[str, tuple[str, ...]] | None:
    """What this machine's ssh client can negotiate, by family, or None.

    Asked once per process with `ssh -Q`, which contacts nothing. An option
    naming an algorithm the client was built without is refused by the client
    before it opens a socket ("Bad SSH2 KexAlgorithms"), so an offer is
    filtered to what the client knows; None, where there is no client to ask,
    filters nothing.
    """
    return _client_algorithms()


# unicon echoes the hop command it types on the jumphost into the dialog, and
# then logs whatever comes back. A transcript that ENDS on that command is
# itself the finding: the jumphost was told to open a session and the far end
# never answered — not with a prompt, not with a password question, not even
# with a refusal.
#
# Anchored at the start of the line so unicon's own decorated announcement of
# the first spawn ("+++ connection to spawn: ssh -l admin ... +++") is not
# mistaken for a hop that went unanswered.
HOP_COMMAND = re.compile(r"^\s*(?:ssh|telnet)\s+(?P<arguments>.*\S)\s*$", re.IGNORECASE)

# Options that take a separate value, so that value is not read as the address.
# `-l <user>` is the one that matters; the rest are cheap to list.
SSH_VALUE_OPTIONS = frozenset(
    "-B -b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w".split()
)

# Linux retries an unanswered SYN six times with exponential backoff — 1, 2, 4,
# 8, 16, 32, 64 — so an address that answers nothing at all keeps the ssh client
# waiting 127 seconds before it can say "Connection timed out".
#
# DEFAULT_CONNECT_TIMEOUT is deliberately shorter than that: an estate should
# not spend over two minutes per dead device, least of all serialised behind a
# per-jumphost login gate. The cost of being shorter is that the client is cut
# off before it can name its own failure, which is why the dialog comes back
# empty and why the hint below has to name it instead.
TCP_SYN_TIMEOUT = 127


def _hop_address(arguments: str) -> str:
    """The address a hop command was aimed at, or "" if it named none.

    Options and their values are skipped, so `ssh -l user 10.0.0.1` and
    `ssh 10.0.0.1 user` — the ADE-OS shell on a Cisco appliance takes the
    username as its second positional argument — both answer 10.0.0.1.
    """
    skip = False
    for token in arguments.split():
        if skip:
            skip = False
            continue
        if token in SSH_VALUE_OPTIONS:
            skip = True
            continue
        if token.startswith("-"):
            continue
        return token.rpartition("@")[2]
    return ""


def _unanswered_hop(dialog: str) -> str | None:
    """The address of a hop command the transcript ends on, nothing following.

    ``None`` when the transcript does not end on a hop: a device that said
    something is diagnosed from what it said, by the rules above. "" when it
    does end on one whose address cannot be picked out — the silence is still
    the finding, there is just no address to quote.
    """
    lines = [line for line in (dialog or "").splitlines() if line.strip()]
    if not lines:
        return None
    match = HOP_COMMAND.match(lines[-1])
    if match is None:
        return None
    return _hop_address(match.group("arguments"))


def _stopped_at_host_key(evidence: str) -> bool:
    """Did the session end on the host-key question, unanswered, or on its refusal?

    unicon answers the question when it recognises it, and the login then
    goes on to fail, or not, for reasons of its own while the question is
    still in the transcript above. Only a transcript that ends on it stopped
    there; unicon's own log lines are not the session's and are passed over.
    The refusal is different: no login follows it on that hop, and through a
    jump host the jump host's prompt comes back below it, so it counts
    wherever it stands.
    """
    lines = [
        line.strip().lower() for line in evidence.splitlines()
        if line.strip() and UNICON_LOG_STAMP not in line
    ]
    if any("host key verification failed" in line for line in lines):
        return True
    if not lines:
        return False
    last = lines[-1]
    return any(marker in last for marker in HOST_KEY_PROMPT_MARKERS) and last.endswith("?")


def connect_failure_hint(
    exc: BaseException,
    double_enable_used: bool,
    dialog: str = "",
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    known_hosts: Path | str | None = None,
    via_jump_host: bool = False,
) -> str | None:
    """Advice for a connect failure whose cause the message does not name.

    unicon reports both a crypto mismatch and a rejected setup command as
    "failed to connect", which reads as an unreachable device and sends people
    to check routing and passwords that were never the problem.

    ``dialog`` is unicon's transcript, and reading it is the point: the ssh
    client's own complaint never reaches the exception. All unicon raises is
    `failed to connect to <name>`, so an exception-only rule would never fire
    on the one failure it was written for.
    """
    evidence = f"{exc}\n{dialog}"
    message = evidence.lower()
    # Before the unknown-key case: a changed key says "Host key verification
    # failed" too, and the two want opposite advice.
    pins = str(known_hosts) if known_hosts else "the estate's known_hosts"
    if any(marker in message for marker in HOST_KEY_CHANGED_MARKERS):
        where = "on the jump host, in its known_hosts" if via_jump_host else f"in {pins}"
        return (
            "the host key for this address has changed since it was pinned. "
            "That is a rebuilt device, or it is worth knowing about — check it, "
            f"and once you are satisfied drop the stale entry {where} with "
            "'ssh-keygen -R <address> -f <file>'. Nothing DiscoNet does will "
            "silence this one"
        )
    if _stopped_at_host_key(evidence):
        if via_jump_host:
            return (
                "the jump host's ssh client asked whether to trust a host key it had "
                "not seen, and DiscoNet answered no: it never accepts a key by itself. "
                "On the jump host, read the key with 'ssh-keyscan <address>', check the "
                "fingerprint against the device, and add it to that host's known_hosts"
            )
        if STRICT_REFUSAL_MARKER not in message:
            return (
                "the ssh client asked whether to trust a host key it had not seen, and "
                "DiscoNet answered no — " + hostkeys.unpinned_advice(pins)
            )
        found = UNPINNED_ADDRESS.search(evidence)
        address = found.group("address") if found else "<address>"
        return hostkeys.unpinned_advice(pins, *_address_and_port(address))
    if any(marker in message for marker in SHORT_HOST_KEY_MARKERS):
        # Reached only where DiscoNet's own client could not take the login
        # over; the reason is in the note the collector adds after this.
        return (
            "the device's RSA host key is under 1024 bits, which OpenSSH refuses before "
            "any option is read (RequiredRSASize only raises that floor), and old IOS "
            "generates 512 by default. DiscoNet logs in to such a device through its own "
            "ssh client where the session starts on this machine. Otherwise the ways in: "
            f"telnet where the device has it enabled ({ALLOW_TELNET_FLAG}), a jump host whose ssh client "
            "still accepts such keys, or a regenerated key on the device "
            "(`crypto key generate rsa modulus 2048`, a configuration change that "
            "is the owner's to make, never DiscoNet's)"
        )
    if any(marker in message for marker in SSH_NEGOTIATION_MARKERS):
        offer = _offered_algorithms(evidence)
        return (
            "the SSH client and the device share no algorithm, so no login was "
            "ever attempted — an older image offering only legacy crypto"
            + (f". The device offered: {offer}" if offer else "")
            + ". Add ssh_options to this device's connection, in the '+' form so "
            "that modern devices in the same testbed keep working (testbed.yaml "
            "carries a worked example on R1)"
        )
    if (
        not double_enable_used
        and any(marker in message for marker in PRIVILEGE_MARKERS)
        and not any(marker in message for marker in AUTH_REFUSAL_MARKERS)
    ):
        # The ssh client's "Permission denied, please try again." is a refused
        # password, not a session setup command the device rejected; advising
        # a second enable for it sends the reader to the wrong end of the login.
        return (
            "the device rejected a session setup command, which is what an "
            "unprivileged session looks like — if this device needs a second "
            f"'enable' after login, set custom: {{{DOUBLE_ENABLE_KEY}: true}} on it"
        )
    # Last, because every rule above reads something the device said and this
    # one fires on there being nothing to read. An ordinary unreachable device
    # still gets no hint: "No route to host" is its own diagnosis, and the
    # transcript does not end on an unanswered hop.
    hop = _unanswered_hop(dialog)
    if hop is not None:
        where = f" to {hop}" if hop else ""
        return (
            f"the jumphost login succeeded and the session{where} was then "
            "asked for and never answered — no prompt, no password question, "
            "not even a refusal, which is why the dialog above ends on that "
            "command. Nothing was typed and no key exchange happened, so "
            "neither credentials nor crypto can be the cause. That silence is "
            "what an address whose SYN goes unanswered looks like from here: "
            "the ssh client on the jumphost is still waiting on a TCP connect "
            f"that will not complete, and the {connect_timeout}s connect "
            f"timeout ends the attempt first, before the client's own "
            f"~{TCP_SYN_TIMEOUT}s could report 'Connection timed out' into the "
            "log. To make the client say it itself, re-run this device with "
            f"--connect-timeout {TCP_SYN_TIMEOUT + 20} and read the dialog "
            "again. A whole location failing this way while other locations "
            "succeed is routing, an ACL or a firewall between the jumphost and "
            "that location — or a management address that is down — rather "
            "than a per-device fault"
        )
    return None


# A failed connect keeps its first line ("failed to connect to <name>") and
# needs room for whatever followed it, which is where the cause actually is.
CONNECT_ERROR_LIMIT = 400

# How much of unicon's SSH dialog to copy into collect.log on a failed connect.
DIALOG_TAIL_LINES = 40


def connect_dialog_tail(path: str | None, start: int = 0) -> str:
    """The tail of unicon's SSH dialog, as it was written.

    Kept unredacted deliberately, and only ever held in memory: it is the
    evidence :func:`connect_failure_hint` reasons over, and redaction is too
    blunt to reason over. The ssh client's own `no matching key exchange
    method found. Their offer: ...` carries the word "key", so the redactor
    takes everything after it — including the algorithm list that names the
    fix. Anything written to disk goes through :func:`_log_connect_dialog`.

    ``start`` is a byte offset to read from. unicon appends a rebuilt
    connection's dialog to the same file, and a second session's evidence is
    what it wrote itself, not the tail of the first.
    """
    if not path:
        return ""
    try:
        with open(path, "rb") as handle:
            handle.seek(start)
            lines = handle.read().decode("utf-8", errors="replace").splitlines()
    except OSError as exc:
        log.debug("could not read the connection log %s: %s", path, exc)
        return ""
    return "\n".join([line for line in lines if line.strip()][-DIALOG_TAIL_LINES:])


def _dialog_size(path: str | None) -> int:
    """How much of a dialog is on disk, so what a later session adds can be read alone."""
    try:
        return Path(path).stat().st_size if path else 0
    except OSError:
        return 0


def _log_connect_dialog(device, path: str | None, dialog: str, secrets: Iterable[str] = ()) -> None:
    """Copy the tail of unicon's SSH dialog into the run log.

    The dialog is the only place the device's own words appear, and it lives in
    a temporary file whose path nobody wants to go hunting for. Copying the end
    of it here means `collect.log` alone answers "what did it actually say".

    It goes through the same redaction as the transcript kept in the
    snapshot, the testbed's secrets included: a password echoed at a prompt
    that names no keyword is invisible to the line redaction alone. That file
    already sits on disk unredacted — it is unicon's, not ours — so this adds
    no exposure, and the copy that lands in the snapshot obeys the rule that
    nothing DiscoNet writes carries a secret.
    """
    # Never silent. A failure with no dialog behind it is the dead end this
    # whole path exists to prevent, so say which kind of nothing was found.
    if not path:
        log.warning(
            "%s: no SSH dialog to show — unicon's connection log could not be "
            "located. Re-run this device on its own with -v to watch the login.",
            device.name,
        )
        return
    if not dialog:
        log.warning(
            "%s: unicon's connection log %s is empty — the ssh client failed "
            "before it said anything. Re-run with -v to watch the login.",
            device.name, path,
        )
        return
    redacted = redact_transcript(dialog, secrets)
    log.warning(
        "%s: last %d line(s) of the SSH dialog (%s):\n%s",
        device.name, len(dialog.splitlines()), path, redacted,
    )


def _unicon_log_path(device, known: str | Path | None = None) -> str | None:
    """Best-effort path to unicon's connection log, which holds the full SSH
    dialog. On a failed connect this is the only place the real cause appears.

    ``known`` is where the connect was told to write it. Where there is one,
    it is the answer when the connection cannot be asked, and nothing is
    looked for by name: a log in the temp directory is then not this
    session's, whatever it is called.
    """
    candidates = []
    try:
        candidates.append(device.default)
    except Exception:  # noqa: BLE001 - no connection was ever instantiated
        pass
    try:
        candidates.extend(device.connectionmgr.connections.values())
    except Exception:  # noqa: BLE001
        pass
    for connection in candidates:
        # On a bare unicon Connection this is a string; on a pyATS device it is
        # the LogFile *service*, which returns the path when called.
        path = getattr(connection, "_logfile", None)
        if not isinstance(path, str) or not path:
            service = getattr(connection, "log_file", None)
            if callable(service):
                try:
                    path = service()
                except Exception:  # noqa: BLE001 - diagnostics must never raise
                    path = None
            else:
                path = service
        if isinstance(path, str) and path:
            return path
    if known is not None:
        return str(known) if Path(known).is_file() else None
    return _recent_unicon_log(device.name)


# unicon's own default: <tempdir>/<device>-<via>-<UTC timestamp>.log, which it
# announces as "+++ <device> logfile <path> +++" as its very first act.
UNICON_LOG_MAX_AGE = 3600
# The via and the timestamp are one word each, so what comes before them is
# the whole device name: `pe-1-*.log` read as a prefix also matched the log of
# a `pe-1-b`.
_UNICON_LOG_TAIL = re.compile(r"-[^-]+-[^-]+\.log")


def _recent_unicon_log(name: str, max_age: float = UNICON_LOG_MAX_AGE) -> str | None:
    """Last resort: find unicon's log for this device on disk, by name.

    Every route above goes through a connection object, and a connect that
    failed early may never have finished building one — which loses the
    transcript exactly when it is the only evidence there is. The file itself
    is written before any of that and outlives all of it.

    The age check keeps a stale log from a previous run out of this run's
    diagnosis; a wrong transcript is worse than none.
    """
    pattern = f"{glob.escape(name)}-*.log"
    try:
        candidates = [
            path
            for path in Path(tempfile.gettempdir()).glob(pattern)
            if _UNICON_LOG_TAIL.fullmatch(path.name[len(name):])
            and path.is_file() and time.time() - path.stat().st_mtime <= max_age
        ]
    except OSError:  # noqa: BLE001 - diagnostics must never raise
        return None
    if not candidates:
        return None
    return str(max(candidates, key=lambda path: path.stat().st_mtime))


def _session_steps(device, platform: "platforms.Platform", asked: bool) -> tuple[list[str], bool]:
    """A platform's session setup, and whether its session gets the second enable.

    A platform with no enable step never gets one, whatever asked for it. On
    IOS-XR `enable` is not a privilege step: an NCS540 hands it to the Linux
    PAM stack, which waits for a password nobody will type, and the session
    never returns another prompt. `--double-enable` on the command line and
    `double_enable` on the testbed are both fleet-wide, so both reach XR
    devices unless the platform refuses here.
    """
    second_enable = asked and platform.has_enable
    if asked and not second_enable:
        log.info("%s: double_enable ignored — %s has no enable step", device.name, platform.label)
    return list(platform.session_setup), second_enable


def _collect_device(
    device,
    policy: CommandPolicy,
    snapshot_root: Path,
    log_stdout: bool = False,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
    verify_reachability: bool = False,
    probe_limit: int = DEFAULT_PROBE_LIMIT,
    features: Iterable[str] | None = None,
    prompts: Iterable[LoginPrompt] = (),
    login_gate: Any = None,
    double_enable: bool = False,
    secrets: Iterable[str] = (),
    credential_set: str | None = None,
    allow_legacy_ssh: bool = False,
    allow_telnet: bool = False,
    known_hosts: Path | str | None = None,
) -> DeviceResult:
    """Connect, run the allowlist, disconnect. Never raises for one device.

    Whatever happened, the session transcript ends up redacted inside the
    snapshot and nowhere else: see :func:`store_connect_log`. An error that
    escapes the collection is this device's error: what it answered before
    is kept, and the other devices are collected as if nothing happened.
    An interrupt still escapes, after the transcript is dealt with.
    """
    outcome = DeviceResult(name=device.name, credential_set=credential_set)
    try:
        _run_device(
            device, policy, snapshot_root, log_stdout, connect_timeout, command_timeout,
            verify_reachability, probe_limit, features, prompts, login_gate, double_enable,
            credential_set, secrets, outcome=outcome,
            allow_legacy_ssh=allow_legacy_ssh, allow_telnet=allow_telnet, known_hosts=known_hosts,
        )
    except Exception as exc:  # noqa: BLE001 - a defect stops one device, not the run
        log.error("%s: collection stopped by an unexpected error", device.name, exc_info=True)
        outcome.error = f"collection stopped by an unexpected error: {summarise_error(exc)}"
    finally:
        # Every exit, an interrupt's included: the clear-text transcript is
        # redacted into connect.log and removed before anything else happens.
        outcome.connect_log = store_connect_log(device, snapshot_root, secrets, outcome.connect_log)
    return outcome


# Opt-ins for the two ways in that weaken a login, read from the command line,
# the testbed's own `custom:` or the device's. Off unless one of them says
# `true`, and a word that is not YAML's true is not a yes.
ALLOW_LEGACY_SSH_KEY = "allow_legacy_ssh"
ALLOW_TELNET_KEY = "allow_telnet"
ALLOW_LEGACY_SSH_FLAG = "--allow-legacy-ssh"
ALLOW_TELNET_FLAG = "--allow-telnet"


def opted_in(device, key: str, flag: bool = False) -> bool:
    """Is ``key`` switched on for this device: by the flag, the device or the testbed?"""
    if flag:
        return True
    for holder in (device, getattr(device, "testbed", None)):
        custom = getattr(holder, "custom", None) or {}
        if hasattr(custom, "get") and custom.get(key) is True:
            return True
    return False


def opt_in_advice(flag: str, key: str) -> str:
    return (
        f"re-run with {flag}, or set `{key}: true` under this device's `custom:` "
        f"or the testbed's"
    )


def _create_private(path: Path) -> None:
    """Create ``path`` empty, readable by its owner only, before unicon writes to it.

    unicon appends to the file it is given and keeps its mode, so a transcript
    that holds the clear-text dialog for as long as the session lasts is never
    readable by another account on this machine.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    except OSError:  # pragma: no cover - a filesystem without modes
        pass
    finally:
        os.close(descriptor)


# How often the -v echo looks for new dialog, and how long a line with no
# newline (a `Password:` prompt, a banner question) waits before it is shown.
ECHO_INTERVAL = 0.2
ECHO_PARTIAL_AFTER = 1.0


def _echo_to_stdout(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


class DialogEcho:
    """`-v`: the login dialog on the terminal as it happens, redacted line by line.

    unicon's own `log_stdout` prints every byte of the session, the
    configuration included, before any redaction could see it. This reads the
    transcript unicon writes instead, from where the login started, and shows
    each line only after :func:`redact_transcript` with the testbed's
    secrets. It runs while a login runs and stops when the session is open:
    the commands that follow are in the raw files and in connect.log,
    redacted whole, which a line at a time could not be.
    """

    def __init__(
        self, path: Path | str, device: str, secrets: Iterable[str] = (),
        write: Callable[[str], None] | None = None,
    ):
        self.path = Path(path)
        self.device = device
        self.secrets = tuple(secrets)
        self.write = write or _echo_to_stdout
        self.offset = _dialog_size(str(self.path))
        self.partial = ""
        self.partial_since = 0.0
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._run, name=f"echo-{device}", daemon=True)

    def _emit(self, line: str) -> None:
        shown = redact_transcript(line, self.secrets)
        if shown.strip():
            self.write(f"{self.device}| {shown}")

    def _read(self, final: bool = False) -> None:
        try:
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read()
        except OSError:
            chunk = b""
        self.offset += len(chunk)
        # A terminal's bare carriage return starts a line too.
        text = (self.partial + chunk.decode("utf-8", errors="replace")).replace("\r\n", "\n").replace("\r", "\n")
        *lines, rest = text.split("\n")
        for line in lines:
            self._emit(line)
        now = time.monotonic()
        if rest != self.partial or not rest:
            self.partial_since = now
        self.partial = rest
        if rest and (final or now - self.partial_since >= ECHO_PARTIAL_AFTER):
            self._emit(rest)
            self.partial = ""

    def _run(self) -> None:
        while not self.stopping.wait(ECHO_INTERVAL):
            self._read()

    def __enter__(self) -> "DialogEcho":
        self.thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.stopping.set()
        self.thread.join()
        self._read(final=True)


def _run_device(
    device,
    policy: CommandPolicy,
    snapshot_root: Path,
    log_stdout: bool = False,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
    verify_reachability: bool = False,
    probe_limit: int = DEFAULT_PROBE_LIMIT,
    features: Iterable[str] | None = None,
    prompts: Iterable[LoginPrompt] = (),
    login_gate: Any = None,
    double_enable: bool = False,
    credential_set: str | None = None,
    secrets: Iterable[str] = (),
    outcome: DeviceResult | None = None,
    allow_legacy_ssh: bool = False,
    allow_telnet: bool = False,
    known_hosts: Path | str | None = None,
) -> DeviceResult:
    # Filled in place where the caller hands one in, so what was collected
    # survives an error that escapes from here.
    outcome = outcome if outcome is not None else DeviceResult(name=device.name, credential_set=credential_set)
    _warn_about_overridden_arguments(device)
    asked_for_second_enable = bool(double_enable) or wants_double_enable(device)
    legacy_allowed = opted_in(device, ALLOW_LEGACY_SSH_KEY, allow_legacy_ssh)
    telnet_allowed = opted_in(device, ALLOW_TELNET_KEY, allow_telnet)
    secrets = tuple(secrets)
    transcript_path = snapshot_root / str(device.name) / CONNECT_LOG_TEMP
    try:
        private.make_dir(transcript_path.parent)
        _create_private(transcript_path)
    except OSError:
        log.debug("could not prepare %s", transcript_path, exc_info=True)

    # An empty username reaches the ssh client as `ssh -l  10.0.0.1`, which
    # it answers with its usage text; unicon then reports the device as
    # unreachable, and the real cause — a credential that never loaded — is
    # nowhere in that message. Say it here, before anything is spawned.
    if login_username(device) == "":
        # The name this device's block resolves: the testbed's own set, or the
        # `_N` set `retry` wrote for it. Naming the wrong one sends the reader
        # to fill in a variable that is already there.
        suffix = "" if credential_set in (None, "1") else f"_{credential_set}"
        outcome.error = NO_USERNAME_HINT.format(env=f"{ENV_USERNAME}{suffix}")
        log.warning("%s: %s", device.name, outcome.error)
        return outcome

    os_name = getattr(device, "os", None)
    if not os_name:
        outcome.error = "device has no 'os' set in the testbed"
        log.warning("%s: %s", device.name, outcome.error)
        return outcome
    outcome.os = os_name
    outcome.platform = str(getattr(device, "platform", "") or "") or None

    try:
        plan = policy.plan_for(os_name)
    except CollectionError as exc:
        outcome.error = str(exc)
        log.warning("%s skipped: %s", device.name, exc)
        return outcome
    platform = platforms.platform_for(os_name)
    if platform is None:
        # The allowlist and the registry are kept in step by a test; this is
        # what a run says if somebody edits one without the other.
        outcome.error = f"os '{os_name}' has an allowlist but no entry in platforms.py"
        log.warning("%s skipped: %s", device.name, outcome.error)
        return outcome
    session_setup, second_enable = _session_steps(device, platform, asked_for_second_enable)
    # What the device proved it runs before any enable was sent, when that
    # had to be asked, and whether that stopped the enable. Kept for the
    # reconnect, which need not ask again.
    identified: dict[str, str] = {}
    # What the session the collection reads already answered, asked to
    # identify the device, by command: kept as that command's sample rather
    # than sent twice. Not the answer before a second enable, which was read
    # on a session not yet privileged, and not one a reconnect left behind.
    answered: dict[str, str] = {}

    prompts = tuple(prompts)
    dialog = login_dialog(prompts)
    if prompts:
        log.debug(
            "%s: %d login prompt(s) will be answered: %s", device.name, len(prompts),
            "; ".join(prompt.describe() for prompt in prompts),
        )
    gate = login_gate if login_gate is not None else contextlib.nullcontext()

    def open_session() -> None:
        extra = {"connect_reply": dialog} if dialog is not None else {}
        # Ordering is the whole point on a double-enable device. unicon runs
        # init_exec_commands as the last step of the connect, which is before
        # the second enable has happened — and an unprivileged session refuses
        # `terminal length 0`, so the connect dies and reports itself as
        # unreachable. Such a session therefore opens sending nothing, enables,
        # and only then sets its terminal.
        #
        # The gate is held across all of it: logins through one jumphost are
        # taken one at a time, two nested `ssh` dialogs racing on the same
        # jumphost interleave their output, and a session is not logged in
        # until it is privileged.
        echo = DialogEcho(transcript_path, str(device.name), secrets) if log_stdout else contextlib.nullcontext()
        with gate, echo:
            device.connect(
                # Never unicon's own: it prints the session unredacted. -v is
                # the DialogEcho above.
                log_stdout=False,
                learn_hostname=True,
                connection_timeout=connect_timeout,
                # unicon's transcript goes into the snapshot rather than the
                # system temp directory, so its whole life is in one place;
                # store_connect_log redacts it the moment the session ends.
                logfile=str(transcript_path),
                init_exec_commands=[] if second_enable else session_setup,
                init_config_commands=SESSION_CONFIG_SETUP,
                **QUIET_CONNECT_ARGUMENTS,
                **extra,
            )
            # From here the login has worked: a session is open on the device,
            # and through a jump host one on that too. If what follows fails,
            # the session is closed here rather than left holding a VTY line,
            # and the jump host's, until the run ends.
            try:
                if second_enable:
                    # The declared OS is often a guess on exactly these devices:
                    # the fleet-wide default, written before any of them answered.
                    # An XR box declared as IOS-XE would be sent `enable` and hang
                    # in PAM, so what it runs is settled first, from the prompt or
                    # from `show version`, which every platform answers before
                    # enable. A device that proves to run an OS with no enable
                    # step is sent nothing more; the check after the connect
                    # logs in again as that OS, or reports the wrong `os:` for
                    # finalize where it cannot. Any other disagreement is left to
                    # that check exactly as before.
                    if "os" not in identified:
                        identified["os"] = identify_before_enable(
                            device, os_name, policy, command_timeout, transcript_path
                        )
                    proven = platforms.platform_for(identified["os"])
                    if proven is not None and identified["os"] != os_name and not proven.has_enable:
                        identified["vetoed"] = identified["os"]
                        return
                    _second_enable(device, command_timeout)
                    for command in session_setup:
                        device.execute(command, timeout=command_timeout)
            except Exception:
                try:
                    device.disconnect()
                except Exception:  # noqa: BLE001 - the failure above is the report
                    log.debug("disconnect from %s failed", device.name, exc_info=True)
                raise

    # Set once a timed-out command left a session that could not be replaced:
    # nothing more is sent to this device, and what was left is not sent.
    session_lost = False

    def reopen_session() -> bool:
        """Start a fresh session so the next command does not read a poisoned buffer.

        A command that timed out left its output half-read: the retry, or the
        command after one that gave up, can read the tail of that answer on
        the same session, which parses into nonsense or into the wrong
        command's files. Reconnecting costs one login and makes the next
        command a clean sample.
        """
        nonlocal session_lost
        try:
            device.disconnect()
        except Exception:  # noqa: BLE001 - the session is already broken
            log.debug("disconnect before retry failed on %s", device.name, exc_info=True)
        try:
            open_session()
            device.default.settings.EXEC_TIMEOUT = command_timeout
        except Exception as exc:  # noqa: BLE001
            log.warning("%s: could not reconnect, nothing more is sent: %s", device.name, exc)
            session_lost = True
            return False
        return True

    def reconnect_as(proven: str) -> str | None:
        """Log in once more, as the OS the login proved. None once that session is open.

        Otherwise the reason the device stays uncollected, to add to the
        mismatch report: "" where no reconnect was tried, because the proven
        OS has no allowlist or the old connection could not be dropped, so the
        report is exactly what it was before the reconnect existed.
        """
        nonlocal os_name, plan, session_setup, second_enable
        platform = platforms.platform_for(proven)
        try:
            proven_plan = policy.plan_for(proven)
        except CollectionError:
            return ""
        if platform is None:
            return ""
        # unicon picks its plugin from device.os when the connection object is
        # built, and disconnect() keeps the object: connecting again would log
        # in under the declared plugin a second time. destroy() drops it, so
        # the next connect builds one for the proven OS. Without that there is
        # no reconnect worth making.
        try:
            device.destroy()
        except Exception:  # noqa: BLE001 - reported as the mismatch it is
            log.debug("could not drop the connection to %s", device.name, exc_info=True)
            return ""
        first_log = outcome.connect_log
        start = _dialog_size(first_log)
        device.os = proven
        # open_session and reopen_session read these when they run, so the
        # reconnect, and a retry after it, run under the proven OS: its
        # allowlist, its session setup and its enable rule.
        os_name, plan = proven, proven_plan
        session_setup, second_enable = _session_steps(device, platform, asked_for_second_enable)
        # Proven already; the new session is not asked again. What the old
        # one answered was read through the wrong plugin, and is not kept.
        identified.clear()
        answered.clear()
        identified["os"] = proven
        log.info("%s: logging in again as %s", device.name, platform.label)
        failure: Exception | None = None
        try:
            open_session()
        except Exception as exc:  # noqa: BLE001 - the mismatch report stands
            failure = exc
        second_log = _unicon_log_path(device, transcript_path)
        second = connect_dialog_tail(second_log, start if second_log == first_log else 0)
        if failure is not None:
            # The exception stays out of the report: its words would reclassify
            # an OS mismatch as whatever it happens to mention, and `retry`
            # and finalize read the report for exactly that.
            log.warning(
                "%s: logging in again as %s failed: %s",
                device.name, proven, summarise_error(failure, CONNECT_ERROR_LIMIT),
            )
            _log_connect_dialog(device, second_log, second, secrets)
            return f"logging in again as {proven} failed too; collect.log has the reason"
        again = detect_os(second)
        if again and again != proven:
            return (
                f"logged in again as {proven}, and that login proved "
                f"{platforms.label_for(again, again)} instead: not collected, "
                f"and not tried a third time"
            )
        return None

    def negotiate_legacy_ssh(
        failure: Exception, transcript: str, connect_log: str | None
    ) -> tuple[Exception | None, str, str | None]:
        """Log in again with the algorithms the device's refusal named.

        An ssh client that shares no algorithm with the device stops before a
        username is typed, so nothing here counts toward a lockout. One family
        is added per login, from the device's own offer, and the loop stops the
        moment a login ends on anything but a negotiation refusal — an open
        session, or a device that has now answered the credentials, whichever
        way. Returns what the last login raised (None for a session that is
        open), the dialog it wrote, and where.
        """
        connection = _cli_connection(device)
        if connection is None or not hasattr(connection, "get"):
            return failure, transcript, connect_log
        if str(connection.get("protocol") or "ssh").lower() != "ssh":
            return failure, transcript, connect_log
        # Through a jump host the ssh that negotiates is the jump host's, and
        # this machine's `ssh -Q` says nothing about what that one can speak.
        known = None if proxy_names(device) else client_algorithms()
        original = str(connection.get("ssh_options") or "")
        added: list[str] = []
        families: set[str] = set()
        while True:
            fix = legacy_ssh_fix(transcript, known)
            if fix is None:
                break
            if fix.family in families:
                legacy_notes.append(
                    f"DiscoNet added {added[-1]} and the ssh client refused the "
                    f"{fix.label} again, so the option never reached it — a proxy hop "
                    f"typed as a literal `command:` takes its options from that command"
                )
                break
            families.add(fix.family)
            if not fix.option:
                legacy_notes.append(
                    f"for the {fix.label} the device offers only "
                    f"{', '.join(fix.unknown)}, which this machine's ssh client cannot "
                    f"speak; no login was attempted, and no testbed line can change that"
                )
                break
            try:
                device.destroy()
            except Exception:  # noqa: BLE001 - reported as the refusal it was
                log.debug("could not drop the connection to %s", device.name, exc_info=True)
                break
            added.append(fix.option)
            connection["ssh_options"] = " ".join(part for part in [original, *added] if part)
            start = _dialog_size(connect_log)
            log.info(
                "%s: the ssh client and the device share no %s (offered: %s); "
                "logging in again with %s",
                device.name, fix.label, ", ".join(fix.offered), fix.option,
            )
            try:
                open_session()
            except Exception as again:  # noqa: BLE001 - read the dialog and decide
                failure = again
                path = _unicon_log_path(device, transcript_path)
                transcript = connect_dialog_tail(path, start if path == connect_log else 0)
                connect_log = path
                if any(marker in transcript.lower() for marker in UNKNOWN_SSH_OPTION_MARKERS):
                    legacy_notes.append(
                        f"this machine's ssh client does not know {fix.option} "
                        f"(OpenSSH 9.1 or later does), so it cannot accept this device's "
                        f"{fix.label}; log in from a machine with a newer client, or through "
                        f"a jump host that has one"
                    )
                    added.pop()
                    connection["ssh_options"] = " ".join(part for part in [original, *added] if part)
                    break
                continue
            outcome.ssh_options = hostkeys.without_policy(connection["ssh_options"], known_hosts)
            log.info("%s: logged in with %s", device.name, outcome.ssh_options)
            return None, transcript, connect_log
        if added and legacy_ssh_fix(transcript, None) is None:
            # Past the negotiation: whatever the device said next, it said to
            # a client it could talk to, and that is worth keeping.
            outcome.ssh_options = hostkeys.without_policy(connection["ssh_options"], known_hosts)
        return failure, transcript, connect_log

    def refuse_legacy_ssh(transcript: str) -> None:
        """Say what the refusal asks for and which opt-in would try it. Nothing is retried."""
        connection = _cli_connection(device)
        if connection is None or not hasattr(connection, "get"):
            return
        if str(connection.get("protocol") or "ssh").lower() != "ssh":
            return
        known = None if proxy_names(device) else client_algorithms()
        fix = legacy_ssh_fix(transcript, known)
        if fix is None or not fix.option:
            return
        legacy_notes.append(
            f"not logged in again with {fix.option}: DiscoNet re-enables legacy SSH "
            f"algorithms only when asked to — "
            + opt_in_advice(ALLOW_LEGACY_SSH_FLAG, ALLOW_LEGACY_SSH_KEY)
        )
        log.info(
            "%s: the device offers only legacy %s; not retried (%s is off)",
            device.name, fix.label, ALLOW_LEGACY_SSH_FLAG,
        )

    def relay_short_host_key(
        failure: Exception, transcript: str, connect_log: str | None
    ) -> tuple[Exception | None, str, str | None]:
        """Log in through DiscoNet's own ssh client where OpenSSH refused the host key's length.

        OpenSSH will not talk to an RSA host key under 1024 bits, and no
        option changes that; the device, the customer's, accepts the login
        all the same. Nothing was sent before the refusal, so this is the
        device's first login attempt, not a second one. Automatic: the relay
        is held to the same pins and is asked for the same password, and the
        device is marked in the manifest so the short key is reported.
        """
        if not is_short_host_key(transcript):
            return failure, transcript, connect_log
        how = relay_connection(device, known_hosts)
        if isinstance(how, str):
            legacy_notes.append(how)
            return failure, transcript, connect_log
        try:
            device.destroy()
        except Exception:  # noqa: BLE001 - reported as the refusal it was
            log.debug("could not drop the connection to %s", device.name, exc_info=True)
            how.undo()
            return failure, transcript, connect_log
        how.apply()
        start = _dialog_size(connect_log)
        log.warning(
            "%s: OpenSSH refuses this device's RSA host key for being under 1024 bits; "
            "logging in through DiscoNet's own ssh client, held to the same pinned key",
            device.name,
        )
        try:
            open_session()
        except Exception as again:  # noqa: BLE001 - the relay's own failure is the report now
            path = _unicon_log_path(device, transcript_path)
            transcript = connect_dialog_tail(path, start if path == connect_log else 0)
            legacy_notes.append(
                # Not "under 1024 bits": finalize reads that phrase as a call
                # for legacy algorithms, and this login already offered them.
                "OpenSSH refused the device's short RSA host key, and the login was made "
                f"through DiscoNet's own ssh client ({legacyssh.CLIENT_NAME}) instead; what "
                "is reported is that login's failure"
            )
            outcome.ssh_client = legacyssh.CLIENT_NAME
            outcome.host_key_bits = how.bits
            return again, transcript, path
        outcome.ssh_client = legacyssh.CLIENT_NAME
        outcome.host_key_bits = how.bits
        log.info("%s: logged in through %s", device.name, legacyssh.CLIENT_NAME)
        return None, transcript, connect_log

    def fall_back_to_telnet(
        failure: Exception, transcript: str, connect_log: str | None
    ) -> tuple[Exception | None, str, str | None]:
        """Log in over telnet where the ssh client cannot be made to talk and TCP/23 answers.

        Only after a refusal that happened before any credential was sent — a
        host key under OpenSSH's floor, an algorithm the retry could not add —
        and only for a device reached directly: a probe from this machine
        says nothing about what a jump host can reach. The block keeps saying
        ssh until finalize writes what worked.
        """
        connection = _cli_connection(device)
        if connection is None or not hasattr(connection, "get"):
            return failure, transcript, connect_log
        if str(connection.get("protocol") or "ssh").lower() != "ssh" or proxy_names(device):
            return failure, transcript, connect_log
        lowered = transcript.lower()
        if not any(marker in lowered for marker in SHORT_HOST_KEY_MARKERS + SSH_NEGOTIATION_MARKERS):
            return failure, transcript, connect_log
        address = _connection_ip(device)
        if not address:
            return failure, transcript, connect_log
        if not telnet_allowed:
            # Not even the port is probed: telnet sends the login in clear,
            # and trying it is the operator's decision, never the tool's.
            legacy_notes.append(
                "telnet was not tried: DiscoNet falls back to telnet, which sends the "
                "login in clear, only when asked to — "
                + opt_in_advice(ALLOW_TELNET_FLAG, ALLOW_TELNET_KEY)
            )
            return failure, transcript, connect_log
        if not port_answers(address, TELNET_PORT):
            legacy_notes.append(f"TCP/{TELNET_PORT} did not answer, so telnet is not a way in either")
            return failure, transcript, connect_log
        try:
            device.destroy()
        except Exception:  # noqa: BLE001 - reported as the refusal it was
            log.debug("could not drop the connection to %s", device.name, exc_info=True)
            return failure, transcript, connect_log
        ssh_options = connection.pop("ssh_options", None)
        connection["protocol"] = TELNET
        connection["port"] = TELNET_PORT
        log.info(
            "%s: the ssh client cannot be made to talk to this device and TCP/%d answers; "
            "logging in over telnet",
            device.name, TELNET_PORT,
        )
        try:
            open_session()
        except Exception as again:  # noqa: BLE001 - the ssh refusal stays the report
            legacy_notes.append(
                f"TCP/{TELNET_PORT} answered, and the login over telnet failed too: "
                f"{summarise_error(again, 200)}"
            )
            connection["protocol"] = "ssh"
            connection.pop("port", None)
            if ssh_options:
                connection["ssh_options"] = ssh_options
            return failure, transcript, connect_log
        outcome.protocol = TELNET
        outcome.ssh_options = None
        log.warning(
            "%s: logged in over telnet; the testbed still says ssh, which `disconet finalize` "
            "corrects. The login crossed the network in clear",
            device.name,
        )
        return None, transcript, connect_log

    # What the legacy-SSH retry has to add to a failure report, so the reader
    # is not told to add an option that was already tried.
    legacy_notes: list[str] = []
    transcript = ""
    try:
        open_session()
    except Exception as exc:  # noqa: BLE001 - warn and continue with other devices
        failure: Exception | None = exc
        # The transcript, not the exception, is where the cause is. unicon
        # raises `failed to connect to <name>` and nothing else, however loudly
        # the ssh client complained on the way. Named apart from `dialog`
        # above, which is the login dialog `open_session` still closes over.
        connect_log = _unicon_log_path(device, transcript_path)
        transcript = connect_dialog_tail(connect_log)
        if legacy_allowed:
            failure, transcript, connect_log = negotiate_legacy_ssh(exc, transcript, connect_log)
        else:
            refuse_legacy_ssh(transcript)
        if failure is not None:
            failure, transcript, connect_log = relay_short_host_key(failure, transcript, connect_log)
        if failure is not None:
            failure, transcript, connect_log = fall_back_to_telnet(failure, transcript, connect_log)
        outcome.connect_log = connect_log
    else:
        failure = None
    if failure is not None:
        exc = failure
        # Not `.splitlines()[0]`: unicon's first line is "failed to connect to
        # <name>", which names nothing. What the device actually said is on the
        # lines after it, so the whole message is collapsed and kept.
        if isinstance(exc, SecondEnableError):
            # The login worked. Saying "unreachable" here would send the reader
            # to the network and the credentials, which are both fine.
            outcome.error = f"logged in, but {summarise_error(exc, CONNECT_ERROR_LIMIT)}"
        else:
            outcome.error = f"connect failed: {summarise_error(exc, CONNECT_ERROR_LIMIT)}"
        outcome.detected_os = detect_os(transcript) or None
        if outcome.detected_os and not platforms.stands_in(outcome.detected_os, os_name):
            # The login worked and the prompt names a different platform. Every
            # other hint is downstream of this one — a second enable that XR
            # refuses, a `terminal length` an XR plugin would not send — so it
            # replaces them rather than joining them.
            hint = os_mismatch_hint(os_name, outcome.detected_os, transcript)
        else:
            hint = connect_failure_hint(
                exc, second_enable, transcript, connect_timeout, known_hosts=known_hosts,
                via_jump_host=bool(proxy_names(device)),
            )
        if hint:
            outcome.error = f"{outcome.error} — {hint}"
        for note in legacy_notes:
            outcome.error = f"{outcome.error}; {note}"
        log.warning("%s unreachable: %s", device.name, outcome.error)
        _log_connect_dialog(device, outcome.connect_log, transcript, secrets)
        return outcome

    # The session is open. Before anything is sent through it, the prompt is
    # read: a device that logged in under the wrong plugin would now be given
    # the wrong allowlist, fail thirty commands one at a time, and be reported
    # as thirty parser problems instead of the one testbed line it actually is.
    outcome.connect_log = _unicon_log_path(device, transcript_path)
    transcript = connect_dialog_tail(outcome.connect_log)
    outcome.detected_os = identified.get("vetoed") or detect_os(transcript) or None
    if not outcome.detected_os:
        # A bare `hostname#` is IOS-XE, classic IOS, NX-OS or ASA, and the
        # declaration is the setup's fleet-wide guess. One `show version`,
        # held to the declared OS's allowlist and kept as the collection's
        # own, settles it before thirty commands are sent under the wrong
        # allowlist; a double-enable session asked it already, before its
        # enable, and is not asked twice.
        if "os" not in identified:
            identified["os"] = identify_before_enable(
                device, os_name, policy, command_timeout, transcript_path, answered
            )
        proven = identified.get("os") or ""
        if proven and not platforms.stands_in(proven, os_name):
            outcome.detected_os = proven
    if outcome.detected_os and not platforms.stands_in(outcome.detected_os, os_name):
        declared = os_name
        outcome.error = "logged in, but " + os_mismatch_hint(
            declared, outcome.detected_os, transcript
        )
        log.warning("%s: %s", device.name, outcome.error)
        _log_connect_dialog(device, outcome.connect_log, transcript, secrets)
        # Once, and only from here: the login worked, so the credentials are
        # not in question, and a second session that proves yet another OS is
        # reported rather than chased.
        refused = reconnect_as(outcome.detected_os)
        if refused is not None:
            if refused:
                outcome.error = f"{outcome.error}; {refused}"
                log.warning("%s: %s", device.name, refused)
            device.os = declared
            try:
                device.disconnect()
            except Exception:  # noqa: BLE001 - cosmetic
                log.debug("disconnect from %s failed", device.name, exc_info=True)
            return outcome
        # Collected as what it proved to be. The manifest keeps the
        # declaration beside it, and finalize corrects the testbed from that.
        outcome.error = None
        outcome.os = os_name
        outcome.declared_os = declared
        outcome.connect_log = _unicon_log_path(device, transcript_path)
        log.warning(
            "%s: logged in again as %s and collected under it; the testbed still "
            "declares os: %s, which `disconet finalize` corrects",
            device.name, os_name, declared,
        )

    outcome.connected = True
    log.info("%s connected (%s)", device.name, os_name)
    try:
        device.default.settings.EXEC_TIMEOUT = command_timeout
    except Exception:  # noqa: BLE001
        log.debug("could not set EXEC_TIMEOUT on %s", device.name, exc_info=True)

    try:
        slugs = unique_slugs(list(plan.selected_parse(features)) + list(plan.raw_only))
        for command in plan.selected_parse(features):
            outcome.commands.append(
                CommandResult(command=command, detail=NOT_SENT_DETAIL) if session_lost else
                _collect_command(
                    device, os_name, command, policy, snapshot_root, device.name,
                    True, command_timeout, reopen_session, slug=slugs[command],
                    answer=answered.pop(command, None),
                )
            )
        for command in plan.raw_only:
            outcome.commands.append(
                CommandResult(command=command, detail=NOT_SENT_DETAIL) if session_lost else
                _collect_command(
                    device, os_name, command, policy, snapshot_root, device.name,
                    False, command_timeout, reopen_session, slug=slugs[command],
                )
            )
        # After the configuration and the tables, because that is where the
        # VRF names come from.
        if not session_lost:
            outcome.commands.extend(
                _collect_per_vrf(
                    device, os_name, policy, snapshot_root, device.name, outcome.commands, command_timeout,
                    reopen_session=reopen_session, not_read=outcome.vrfs_not_read,
                )
            )
        if verify_reachability:
            if plan.probe:
                if not session_lost:
                    outcome.probed = True
                    outcome.commands.extend(
                        _probe_device(
                            device, os_name, policy, snapshot_root, device.name,
                            outcome.commands, probe_limit, DEFAULT_PROBE_TIMEOUT,
                            reopen_session=reopen_session,
                        )
                    )
            else:
                log.warning(
                    "%s: --verify-reachability given but os '%s' lists no probe in %s",
                    device.name, os_name, policy.source,
                )
    except Exception:
        # The caller records the error. Every planned command with no result
        # yet, the one the defect stopped included, is recorded too, so the
        # gap list says what was never collected and not only what was
        # answered badly.
        kept = {result.command for result in outcome.commands}
        outcome.commands.extend(
            CommandResult(command=command, detail=NOT_SENT_AFTER_ERROR_DETAIL)
            for command in list(plan.selected_parse(features)) + list(plan.raw_only)
            if command not in kept
        )
        raise
    finally:
        try:
            device.disconnect()
        except Exception:  # noqa: BLE001 - disconnect failures are cosmetic
            log.debug("disconnect from %s failed", device.name, exc_info=True)

    return outcome


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------

# Keys pyATS accepts at the top level of a testbed file. Everything else —
# servers, credentials, custom — belongs inside the `testbed:` block, and
# getting that wrong is the most common testbed editing mistake.
TOP_LEVEL_TESTBED_KEYS = ("testbed", "devices", "topology")


# What pyATS reports when a connection's `ip:` holds more than an address. The
# schema runs the value through translate_host, which tries to resolve the
# whole string as a hostname and fails somewhere deep in IDNA encoding.
SWALLOWED_ADDRESS_KEYS = ("ssh_options", "-o ", "arguments", "proxy")


def _swallowed_address_hint(message: str) -> str:
    """Advice for an `ip:` that has eaten the lines below it.

    YAML folds a more-indented continuation line into the scalar above it, so a
    key that lost its name — or never had one, because the line above it was
    left dangling — silently becomes part of the address. The value pyATS
    quotes back makes it obvious once you know to look; the exception it comes
    wrapped in talks about IDNA labels and does not.
    """
    address = re.search(r"translate_host\('([^']*)'", message)
    swallowed = address.group(1) if address else ""
    if not any(key in swallowed for key in SWALLOWED_ADDRESS_KEYS):
        return (
            "\n  A connection's 'ip:' is not an address pyATS can resolve. "
            "Check it for stray text."
        )
    head = swallowed.split()[0] if swallowed.split() else "the address"
    return (
        f"\n  A connection's 'ip:' has swallowed the lines below it: it holds "
        f"'{head}' followed by what should be separate keys."
        f"\n  YAML folds a more-indented line into the value above it, so a key "
        f"whose name went missing — ssh_options is the usual one — becomes part "
        f"of the address."
        f"\n  Give it its name back, at exactly the same indentation as 'ip:':"
        f"\n      ip: {head}"
        f"\n      ssh_options: \"-o KexAlgorithms=+... -o HostKeyAlgorithms=+ssh-rsa\""
    )


def _load_testbed(loader, testbed_path: Path | str):
    """Load a testbed, turning pyATS schema errors into actionable advice."""
    try:
        return loader(str(testbed_path))
    except Exception as exc:  # noqa: BLE001 - pyATS raises several schema types
        message = str(exc)
        hint = ""
        if "Unsupported keys" in message:
            offending = re.findall(r"'([^']+)'", message)
            names = ", ".join(f"'{name}'" for name in offending) or "that key"
            hint = (
                f"\n  {names} is not allowed at the top level of a testbed file. "
                f"Only {', '.join(TOP_LEVEL_TESTBED_KEYS)} are."
                f"\n  Indent it so it sits inside the 'testbed:' block."
            )
        elif "translate_host" in message:
            hint = _swallowed_address_hint(message)
        raise CollectionError(
            f"could not load testbed {testbed_path}: {type(exc).__name__}: {message}{hint}"
        ) from exc


def snapshot_dir(base_dir: Path | str, stamp: datetime | None = None) -> Path:
    """Location of one snapshot: ``<base>/<UTC timestamp>``."""
    stamp = stamp or datetime.now(timezone.utc)
    return Path(base_dir) / stamp.strftime("%Y%m%dT%H%M%SZ")


def _new_snapshot_root(base_dir: Path | str, stamp: datetime) -> Path:
    """A directory for a new run, made here and never one that was there.

    The name is the second the run started, and a merge in that second, or
    another collect, has it already: the run wrote its devices and its
    manifest into theirs. The next free name is taken instead, `<stamp>-2`
    and on, which sorts after the one it follows; nothing reads a snapshot's
    time from its name. The directory is made, not checked for, so two runs
    racing for one name cannot both have it.
    """
    first = snapshot_dir(base_dir, stamp)
    # The snapshot base is this tool's own directory: made 0700, and one an
    # earlier version left open to other accounts is tightened and said.
    private.make_dir(first.parent)
    private.tighten(first.parent)
    root, number = first, 1
    while True:
        try:
            return private.make_child_dir(root)
        except FileExistsError:
            number += 1
            root = first.with_name(f"{first.name}-{number}")


def _attach_run_log(snapshot_root: Path) -> logging.Handler:
    """Human-readable per-run log alongside the collected data."""
    handler = logging.FileHandler(snapshot_root / "collect.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s"))
    handler.setLevel(logging.DEBUG)
    logging.getLogger("netstate").addHandler(handler)
    return handler


SESSION_LOG_NAME = "session.log"

# Credential fields to scrub out of a transcript, whatever else is in it.
CREDENTIAL_KEYS = ("password", "passphrase", "token", "secret", "enable_password")


def testbed_secrets(testbed) -> set[str]:
    """Every credential literal in the testbed, so a transcript can lose them.

    Every device, not only the ones being collected: the password that gets
    typed into a jumphost belongs to the jumphost, which is never collected
    from at all.

    The answers to `custom.login_prompts` are among them: what a login is
    told can be a password or a one-time code (LoginPrompt.describe keeps
    them out of collect.log for that reason), and a jump host that echoes
    it writes it into the transcript. They are read as written, unchecked:
    an entry the run would refuse still names what was meant to be typed.

    So are the testbed's own `credentials:` and every server's under
    `servers:`: a jump host written there is logged into with them, and a
    hand-written testbed may hold them as literals rather than `%ENV{}`.
    """
    found: set[str] = set()

    def credential_texts(holder: Any) -> list[str]:
        texts: list[str] = []
        if not hasattr(holder, "get"):
            holder = {"credentials": getattr(holder, "credentials", None)}
        # A server may carry a bare `password:` beside `credentials:`.
        texts.extend(_plaintext(holder.get(key)) for key in CREDENTIAL_KEYS)
        credentials = holder.get("credentials") or {}
        for credential in list(getattr(credentials, "values", list)() or []):
            for key in CREDENTIAL_KEYS:
                value = credential.get(key) if hasattr(credential, "get") else None
                texts.append(_plaintext(value))
        return texts

    shared = credential_texts(testbed)
    servers = getattr(testbed, "servers", None) or {}
    for server in list(getattr(servers, "values", list)() or []):
        shared.extend(credential_texts(server))
    found.update(text for text in shared if len(text) >= 4)
    devices = getattr(testbed, "devices", None) or {}
    for device in list(getattr(devices, "values", list)() or []):
        texts: list[str] = []
        credentials = getattr(device, "credentials", None) or {}
        for credential in list(getattr(credentials, "values", list)() or []):
            for key in CREDENTIAL_KEYS:
                value = credential.get(key) if hasattr(credential, "get") else None
                texts.append(_plaintext(value))
        custom = getattr(device, "custom", None) or {}
        prompts = custom.get(LOGIN_PROMPTS_KEY) if hasattr(custom, "get") else None
        for entry in prompts if isinstance(prompts, (list, tuple)) else ():
            response = entry.get("response") if hasattr(entry, "get") else None
            texts.append(response if isinstance(response, str) else "")
        # Two characters would match half the transcript.
        found.update(text for text in texts if len(text) >= 4)
    return found


# unicon's transcript of one device's session: the login dialog and every
# command. During the session it is written where `logfile=` points, in the
# clear, because unicon writes it; the moment the session is over it is
# redacted into CONNECT_LOG_NAME and the original is deleted. That is the
# window in which an unredacted file exists, and the README says so.
CONNECT_LOG_NAME = "connect.log"
CONNECT_LOG_TEMP = "connect.log.tmp"


# unicon's stamp on a DEBUG line. Each is a repr copy of a buffer whose line
# breaks are escaped, so a secret inside one sits mid-line where no line rule
# looks; the plain lines of the same dialog are in the transcript anyway.
UNICON_DEBUG_STAMP = f"{UNICON_LOG_STAMP}DEBUG:"


def _secret_spellings(secrets: Iterable[str]) -> list[str]:
    """Each secret as typed and as a repr prints it, longest first.

    A repr doubles a backslash and escapes the quote around it, so a password
    holding either is a different string once printed that way. Longest first,
    so a password containing a shorter one is masked whole instead of being
    left with a readable tail.
    """
    found: set[str] = set()
    for secret in secrets:
        if not secret:
            continue
        escaped = secret.replace("\\", "\\\\")
        found.update((secret, escaped, escaped.replace("'", "\\'"), escaped.replace('"', '\\"')))
    return sorted(found, key=len, reverse=True)


def redact_transcript(text: str, secrets: Iterable[str] = ()) -> str:
    """A session transcript with the testbed's credentials and every secret-bearing line taken out.

    unicon's DEBUG lines are dropped whole rather than redacted: the device's
    words in them are also on the transcript's plain lines, which are.
    The credentials are taken out before the control characters are and
    again after: a password that holds one is found as typed, and one an
    escape sequence splits on the terminal is found once it is gone.
    """
    text = "\n".join(line for line in text.split("\n") if UNICON_DEBUG_STAMP not in line)
    spellings = _secret_spellings(secrets)
    for secret in spellings:
        text = text.replace(secret, REDACTION_MARKER)
    text = clean_text(text)
    for secret in spellings:
        text = text.replace(secret, REDACTION_MARKER)
    redacted, _ = redact(text)
    return redacted


def store_connect_log(
    device, snapshot_root: Path, secrets: Iterable[str] = (), located: str | None = None
) -> str | None:
    """Redact unicon's transcript into the snapshot and delete the original.

    Every place the transcript can be is read: the file the connect asked
    for and the one unicon says it wrote. A log in the temp directory by the
    device's name is not one of them: the connect asked for its own file, so
    that log is another session's. The first found is redacted into
    ``<device>/connect.log``; every one found is deleted. Returns the redacted file's path relative to the
    snapshot, which is what the manifest records, or None when there was no
    transcript at all.
    """
    name = str(getattr(device, "name", "") or "")
    if not name:
        return None
    device_dir = snapshot_root / name
    if not device_dir.resolve().is_relative_to(snapshot_root.resolve()):
        return None
    candidates: list[Path] = [device_dir / CONNECT_LOG_TEMP]
    for found in (located, _unicon_log_path(device, candidates[0])):
        if found and Path(found) not in candidates:
            candidates.append(Path(found))
    target = device_dir / CONNECT_LOG_NAME
    written: str | None = None
    for path in candidates:
        if path == target or not path.is_file():
            continue
        # The file a login was given before it started, which no login ever
        # wrote to: there is no transcript, only the empty file to remove.
        if written is None and path.stat().st_size > 0:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                private.write_text(target, redact_transcript(text, secrets))
                written = f"{name}/{CONNECT_LOG_NAME}"
            except OSError as exc:
                log.warning("%s: could not keep the session transcript: %s", name, exc)
        # The original goes whether or not its redacted copy was written: it
        # is the clear text, and a transcript lost is a gap where one kept
        # would be the password on disk.
        try:
            path.unlink()
        except OSError as exc:
            log.warning("%s: an unredacted transcript is still at %s: %s", name, path, exc)
    return written


def sweep_connect_logs(base_dir: Path | str, names: Iterable[str], secrets: Iterable[str] = ()) -> int:
    """Deal with transcripts a crashed run left in the clear, before anything else runs.

    A `connect.log.tmp` under any snapshot is redacted into its `connect.log`
    and removed; unicon's own `<device>-*.log` in the temp directory, for any
    device the testbed names, is removed. Returns how many files were dealt
    with.
    """
    handled = 0
    base = Path(base_dir)
    if base.is_dir():
        for snapshot in sorted(path for path in base.iterdir() if path.is_dir()):
            handled += sweep_snapshot_transcripts(snapshot, secrets)
    temp = Path(tempfile.gettempdir())
    for name in sorted({str(n) for n in names if n}):
        try:
            stale = [p for p in temp.glob(f"{glob.escape(name)}-*.log") if p.is_file()]
        except OSError:
            continue
        for path in stale:
            try:
                path.unlink()
                handled += 1
            except OSError as exc:
                log.warning("an unredacted transcript is still at %s: %s", path, exc)
    if handled:
        log.info("%d transcript(s) from an earlier run redacted or removed", handled)
    return handled


def sweep_snapshot_transcripts(snapshot_root: Path, secrets: Iterable[str] = ()) -> int:
    """Redact and remove every `connect.log.tmp` still in one snapshot. Returns how many."""
    handled = 0
    for leftover in sorted(Path(snapshot_root).glob(f"*/{CONNECT_LOG_TEMP}")):
        try:
            text = leftover.read_text(encoding="utf-8", errors="replace")
            target = leftover.with_name(CONNECT_LOG_NAME)
            if not target.exists():
                private.write_text(target, redact_transcript(text, secrets))
        except OSError as exc:
            log.warning("could not redact %s: %s", leftover, exc)
        try:
            leftover.unlink()
            handled += 1
        except OSError as exc:
            log.warning("an unredacted transcript is still at %s: %s", leftover, exc)
    return handled


def write_session_log(snapshot_root: Path, results: Iterable[DeviceResult]) -> None:
    """`session.log`: every device's SSH dialog in one file, as its connect.log keeps it.

    Built after the run from the transcripts :func:`store_connect_log`
    redacted whole, not written a record at a time as unicon logs. unicon's
    connection loggers do not pass their records up, so a handler on its
    logger saw nothing; and one record at a time defeats the redaction even
    where it sees them: the timestamp in front stops the anchored rules, a
    chunk can split a secret from its keyword, and a Junos block is never
    seen whole.
    """
    parts: list[str] = []
    for result in sorted(results, key=lambda result: str(result.name)):
        path = snapshot_root / result.connect_log if result.connect_log else None
        try:
            text = path.read_text(encoding="utf-8") if path is not None and path.is_file() else None
        except OSError as exc:
            log.warning("%s: could not read %s for the session log: %s", result.name, path, exc)
            text = None
        if text is None:
            parts.append(f"===== {result.name}: no session transcript was kept =====\n")
        else:
            parts.append(f"===== {result.name} ({result.connect_log}) =====\n{text.rstrip()}\n")
    try:
        private.write_text(snapshot_root / SESSION_LOG_NAME, "\n".join(parts))
    except OSError as exc:
        log.warning("could not write %s: %s", snapshot_root / SESSION_LOG_NAME, exc)


def estate_facts(snapshot_root: Path | str, db: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Per device, what the estate table keeps that the manifest does not.

    The platform, the software and the chassis serials, read through the
    registry from what is on disk, as the topology reads them: the parse,
    and the text where the parser failed (a Junos `show chassis hardware`,
    a release Genie does not read). The serials are what make one box
    reached under two names one row rather than two, so the rows have to
    be folded on the serials the topology folds on; a device that printed
    none keeps an empty column rather than an invented one. ``db`` is the
    database the run is stored in, where that is not the one beside it: a
    merge of pruned runs has its outputs there and nowhere else.
    """
    try:
        snapshot = Snapshot.load(snapshot_root, db=db)
    except (OSError, ValueError, CollectionError):
        return {}
    facts: dict[str, dict[str, Any]] = {}
    try:
        for name, device in snapshot.devices.items():
            if not platforms.platform_for(device.get("os")):
                continue
            read = device_version(snapshot, name)
            serials = device_serials(snapshot, name)
            # The estate table's rows carry the testbed name the run was ingested
            # under; the hostname the device gave rides along as a fact.
            facts[snapshot.testbed_name(name)] = {
                "platform": read.platform or None,
                "software": read.software or None,
                "serial": ", ".join(serials) or None,
                "hostname": name,
            }
    finally:
        # Read while the run is being stored: a reader still open when the
        # writer closes keeps the run in disconet.db-wal.
        snapshot.close()
    return facts

def record_snapshot(
    manifest: dict[str, Any],
    snapshot_root: Path,
    db_path: Path | str,
    prune_files: bool = False,
) -> int | None:
    """Fold a finished run into the estate database. Never fails the run.

    A collection that reached devices has already done the part that cannot be
    repeated cheaply — the logins, the sessions, the commands. Losing that
    because SQLite could not open a file on a read-only share would be absurd,
    so every failure here is a warning and the snapshot directory stands on its
    own exactly as it always did.

    ``prune_files`` deletes the per-command text files afterwards, and only
    after the ingest has been confirmed by reading the run back out: a run
    with a file the database holds nothing for keeps every file it has.
    """
    snapshot_id = str(manifest.get("snapshot_id") or snapshot_root.name)
    try:
        connection = store.connect(db_path)
    except sqlite3.Error as exc:  # noqa: BLE001 - the snapshot is already safe
        log.warning("estate database unavailable at %s: %s", db_path, exc)
        return None
    try:
        rows = store.ingest(connection, snapshot_root, manifest)
        store.update_estate(connection, snapshot_id, facts=estate_facts(snapshot_root))
        stored = store.has_snapshot(connection, snapshot_id)
        unheld = store.unheld_files(connection, snapshot_root, manifest) if prune_files and stored else []
    except (sqlite3.Error, OSError) as exc:  # noqa: BLE001
        log.warning("could not store this run in %s: %s", db_path, exc)
        return None
    finally:
        store.checkpoint_and_close(connection)

    if prune_files and stored and unheld:
        # Pruned around them, the run would read as neither pruned nor whole,
        # so it is left whole; the database still holds everything else.
        log.warning(
            "kept this run's per-command files: the estate database could not read %d of them "
            "and holds nothing for them, so the files are the only copy: %s",
            len(unheld), ", ".join(unheld),
        )
    elif prune_files and stored:
        removed = store.prune_files(snapshot_root)
        log.info("pruned %d per-command file(s); the estate database holds them now", removed)
    return rows


def run_collect(
    testbed_path: Path | str,
    base_dir: Path | str = "snapshots",
    devices: Iterable[str] | None = None,
    commands_file: Path | str = DEFAULT_COMMANDS_FILE,
    log_stdout: bool = False,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
    verify_reachability: bool = False,
    probe_limit: int = DEFAULT_PROBE_LIMIT,
    features: Iterable[str] | None = None,
    session_log: bool = False,
    mode: str = DEFAULT_DISCOVERY_MODE,
    double_enable: bool = False,
    demo: bool = False,
    db_path: Path | str | None = None,
    prune_files: bool = False,
    crawl: bool = False,
    crawl_depth: int = DEFAULT_CRAWL_DEPTH,
    crawl_limit: int = DEFAULT_CRAWL_LIMIT,
    crawl_scope: Iterable[str] = (),
    device_factory: Callable[[Any, "Candidate", Any], Any] | None = None,
    estate: str = "",
    retry_of: str = "",
    allow_legacy_ssh: bool = False,
    allow_telnet: bool = False,
    known_hosts: Path | str | None = None,
    confirm_host_key: "hostkeys.Confirm | None" = None,
) -> dict[str, Any]:
    """Collect structured + raw state for every selected device.

    With ``crawl`` the run goes on to the switches the collected devices
    named over CDP or LLDP — those with a management address inside
    ``crawl_scope``, reporting the Bridge capability, whose OS the neighbour's
    description names — to ``crawl_depth`` hops and ``crawl_limit`` devices in
    all, with the same allowlist and credentials. Every device it declined
    is in the manifest with the reason. ``device_factory`` builds the pyATS
    device for a crawled address; the default builds a real one, and a test
    hands in a fake.

    Returns the manifest dict, which is also written to
    ``<base_dir>/<UTC timestamp>/manifest.json``.

    ``features`` names the optional protocol and service groups to collect;
    ``None`` collects every group the allowlist offers. A deselected group is
    simply not sent, and the manifest records the choice so the document can
    say a protocol was not looked for rather than that it is absent.

    ``session_log`` writes the whole SSH dialog, login included, to
    ``session.log`` in the snapshot. It is the only place a login failure
    explains itself. It is joined at the end of the run from each device's
    ``connect.log``, which has already lost every credential in the testbed
    and every line that names a secret.

    ``mode`` is recorded and sent to no device: it is how much a link must
    prove before the topology counts it, and the same snapshot can be rebuilt
    either way afterwards. It lives in the manifest so a topology built later
    defaults to the reading the engineer asked for at collection time.

    ``estate`` is the name of the estate the run belongs to, recorded in the
    manifest and sent to no device; the deliverables are named after it.

    ``retry_of`` is the run whose missed devices this one collects again, as
    a retry round does. Recorded so the run, which holds those few devices
    only, is never read as the estate in place of that run.

    With ``verify_reachability`` the run additionally pings the neighbour
    addresses each device has learned. This is the one part of DiscoNet that
    sends something other than a show command, so it stays off unless asked
    for; see :class:`ProbePolicy` handling in :class:`CommandPolicy`.

    ``allow_legacy_ssh`` and ``allow_telnet`` are the two ways in that weaken
    a login, off unless asked for here or in the testbed's `custom:`. Off, a
    refused negotiation is reported with the opt-in that would try it, and
    nothing is retried.

    Every ssh session this machine opens is held to the host keys pinned in
    ``known_hosts`` (default: `known_hosts` beside the testbed), strictly.
    ``confirm_host_key``, given only where someone is at a terminal, is asked
    about each unpinned key before the first login; see :mod:`netstate.hostkeys`.
    """
    from genie.testbed import load as load_testbed  # imported late: heavy dependency

    policy = CommandPolicy.load(commands_file)  # validated before any connection
    testbed = _load_testbed(load_testbed, testbed_path)

    # A jumphost is in the testbed because other devices are reached through
    # it, not because it is part of the network being documented. Collecting
    # from it would report a Linux box as an unreachable router. Naming it in
    # --devices still collects it: an explicit request is an answer.
    jumphosts = {
        name
        for device in testbed.devices.values()
        for name in proxy_names(device)
        if name in testbed.devices
    }
    if devices:
        selected = list(devices)
    else:
        selected = [name for name in testbed.devices if name not in jumphosts]
        if jumphosts:
            log.info(
                "not collected, used only to reach other devices: %s",
                ", ".join(sorted(jumphosts)),
            )
    unknown = [name for name in selected if name not in testbed.devices]
    if unknown:
        raise CollectionError(
            f"device(s) not in testbed {testbed_path}: {', '.join(unknown)} "
            f"(available: {', '.join(testbed.devices)})"
        )
    if not selected:
        raise CollectionError(f"testbed {testbed_path} defines no devices")
    # What `--devices` left out of the testbed, so the manifest of a run of
    # a few named devices says it holds part of the estate, as a retry
    # round's does. Its requested devices alone cannot say so: the testbed
    # it was run against may be gone or have changed by the time it is read.
    not_requested = [
        name for name in testbed.devices if name not in jumphosts and name not in selected
    ]

    # Validated before anything is contacted, exactly as the allowlist is: a
    # malformed login prompt should stop the run, not fail one device at a time
    # halfway through.
    logins = {name: login_prompts(testbed.devices[name], testbed) for name in selected}
    for name, prompts in logins.items():
        if prompts:
            log.info(
                "%s: %d login prompt(s) declared in the testbed will be answered",
                name, len(prompts),
            )

    # One lock per jumphost, built here while the run is still single-threaded.
    gates: dict[tuple[str, ...], threading.Lock] = {}
    for name in selected:
        key = proxy_names(testbed.devices[name])
        if key and key not in gates:
            gates[key] = threading.Lock()

    # The crawl fence is read before anything is written, as the allowlist and
    # the login prompts are: a fence that cannot be used stops the run here,
    # not after an empty snapshot directory and its log already exist.
    try:
        fence = parse_fence(crawl_scope) if crawl else []
    except ValueError as exc:
        raise CollectionError(f"the crawl fence is a list of subnets: {exc}") from exc
    if crawl and not fence:
        raise CollectionError(
            "--crawl needs a fence: the subnets the address file declared (kept in "
            "the estate plan) or --crawl-scope. A crawl with no fence would log into "
            "whatever the neighbours name, which may not be yours."
        )
    crawl_record = (
        CrawlRecord(fence=[str(n) for n in fence], depth=crawl_depth, limit=crawl_limit)
        if crawl else None
    )

    pins = Path(known_hosts) if known_hosts is not None else hostkeys.known_hosts_path(testbed_path)
    connection_policy = {
        "allow_legacy_ssh": bool(allow_legacy_ssh),
        "allow_telnet": bool(allow_telnet),
        "host_keys": "strict",
        "known_hosts": str(pins),
    }

    started = datetime.now(timezone.utc)
    snapshot_root = _new_snapshot_root(base_dir, started)
    handler = _attach_run_log(snapshot_root)

    # Every device as it finishes, whatever then stops the run: an interrupted
    # run keeps these in its manifest.
    finished: list[DeviceResult] = []
    # The devices whose collection is under way at this moment. Empty once the
    # pool has drained; a run that stopped waiting for it names what is left.
    in_session: set[str] = set()
    results: list[DeviceResult] = []
    manifest: dict[str, Any] | None = None
    secrets: set[str] = set()
    # Everything after the run log is attached is inside this, so whatever
    # stops the run, however early, detaches it.
    try:
        log.info(
            "DiscoNet %s collecting %d device(s) into %s",
            __version__, len(selected), snapshot_root,
        )
        log.info("allowlist: %s", policy.source)
        chosen = tuple(policy.available_features if features is None else features)
        skipped = tuple(key for key in policy.available_features if key not in chosen)
        log.info(
            "collecting: %s",
            ", ".join(feature_label(key) for key in chosen) or "base state only",
        )
        if skipped:
            log.info(
                "not collected by request: %s",
                ", ".join(feature_label(key) for key in skipped),
            )
        if double_enable:
            log.info(
                "second enable forced on for every device in this run "
                "(--double-enable overrides the testbed)"
            )
        if verify_reachability:
            log.warning(
                "reachability verification enabled: this sends ICMP probes (ping) to "
                "learned neighbour addresses, at most %d per device", probe_limit,
            )

        if allow_legacy_ssh:
            log.warning(
                "%s: a device whose ssh client refuses the negotiation is logged into again "
                "with the legacy algorithms it offered", ALLOW_LEGACY_SSH_FLAG,
            )
        if allow_telnet:
            log.warning(
                "%s: a device ssh cannot reach directly is tried over telnet, which sends "
                "the login in clear", ALLOW_TELNET_FLAG,
            )
        log.info("host keys: strict, pinned in %s", pins)

        secrets = testbed_secrets(testbed)
        # Before a single login: a transcript a crashed run left in the clear is
        # redacted or removed now, not after another hour of collecting.
        sweep_connect_logs(base_dir, list(getattr(testbed.devices, "keys", list)() or []), secrets)

        held: set[str] = set()

        def hold_to_pins(device) -> None:
            if device.name in held:
                return
            held.add(device.name)
            for holder in [device, *(testbed.devices[name] for name in proxy_names(device) if name in testbed.devices)]:
                overridden = hostkeys.apply(holder, pins)
                if overridden:
                    log.warning(
                        "%s: the testbed's own %s is overridden: host keys are checked "
                        "strictly against %s", holder.name, ", ".join(sorted(set(overridden))), pins,
                    )

        for name in selected:
            hold_to_pins(testbed.devices[name])
        if confirm_host_key is not None:
            reached = [testbed.devices[name] for name in selected]
            reached += [
                testbed.devices[hop] for name in selected
                for hop in proxy_names(testbed.devices[name]) if hop in testbed.devices
            ]
            hostkeys.confirm_first_use(reached, pins, confirm_host_key)

        if session_log:
            log.info(
                "SSH session transcript: %s, joined from each device's connect.log at the end "
                "of the run (credentials replaced with %s)",
                snapshot_root / SESSION_LOG_NAME, REDACTION_MARKER,
            )

        if crawl_record is not None:
            log.info(
                "crawl: up to %d switch(es) to %d hop(s) inside %s", crawl_limit, crawl_depth,
                ", ".join(crawl_record.fence),
            )

        # Which credential set each block names, read from the text before the
        # first login: the manifest records it, and a set that resolved to nothing
        # is reported under its own name.
        credential_sets = _credential_sets_of(testbed_path)

        def collect_one(
            name: str, arrived: Callable[[DeviceResult], None] | None = None
        ) -> DeviceResult:
            in_session.add(name)
            try:
                # A crawled switch joins the testbed mid-run, after the pins
                # were applied to the rest.
                hold_to_pins(testbed.devices[name])
                result = _collect_device(
                    testbed.devices[name], policy, snapshot_root, log_stdout,
                    connect_timeout, command_timeout, verify_reachability,
                    probe_limit, chosen, logins[name],
                    gates.get(proxy_names(testbed.devices[name])), double_enable,
                    secrets, credential_sets.get(name),
                    allow_legacy_ssh=allow_legacy_ssh, allow_telnet=allow_telnet,
                    known_hosts=pins,
                )
                finished.append(result)
            finally:
                in_session.discard(name)
            if arrived is not None:
                arrived(result)
            return result

        def collect_wave(
            names: list[str], arrived: Callable[[DeviceResult], None] | None = None
        ) -> list[DeviceResult]:
            pool = ThreadPoolExecutor(max_workers=max(1, workers))
            futures = [pool.submit(collect_one, name, arrived) for name in names]
            try:
                return [future.result() for future in futures]
            except BaseException:
                # Ctrl-C: a device not yet started is not started. One already
                # in a session finishes it, so its transcript is redacted and
                # its answers are kept; the drain below waits for it.
                for future in futures:
                    future.cancel()
                raise
            finally:
                _drain(pool, futures, in_session)

        with _hangup_as_interrupt():
            results = collect_wave(selected)
            if crawl_record is not None:
                _crawl(
                    testbed, policy, snapshot_root, started, testbed_path, results, selected,
                    logins, gates, chosen, skipped, connect_timeout, command_timeout,
                    verify_reachability, mode, double_enable, demo, crawl_record, fence,
                    collect_wave, device_factory or crawled_device,
                )
        manifest = _build_manifest(
            snapshot_root, started, testbed_path, policy, selected, results,
            connect_timeout, command_timeout, verify_reachability, chosen, skipped,
            mode, double_enable, demo, crawl_record, estate, retry_of, not_requested,
            finished_at=datetime.now(timezone.utc),
        )
        manifest["connection_policy"] = connection_policy
        _write_json(snapshot_root / "manifest.json", manifest)
        record_snapshot(
            manifest,
            snapshot_root,
            db_path if db_path is not None else store.default_path(base_dir),
            prune_files=prune_files,
        )
        summary = manifest["summary"]
        log.info(
            "collection finished: %d/%d device(s) reachable, %d parsed, %d empty, "
            "%d unparsed, %d raw, %d failed",
            summary["devices_connected"], summary["devices_total"],
            summary["commands_parsed"], summary["commands_empty"],
            summary["commands_unparsed"], summary["commands_raw"],
            summary["commands_failed"],
        )
    except BaseException as exc:
        if manifest is None and finished:
            # Copies, the devices in session first: one the drain stopped
            # waiting for is still being collected and may finish meanwhile,
            # and read in this order it is in one list or both, never neither.
            still = sorted(in_session)
            _keep_interrupted_run(
                exc, list(finished), snapshot_root, started, testbed_path, policy, selected,
                connect_timeout, command_timeout, verify_reachability, chosen, skipped,
                mode, double_enable, demo, crawl_record, estate, retry_of, not_requested,
                in_session=still, connection_policy=connection_policy,
            )
        raise
    finally:
        # A session the drain stopped waiting for has not redacted its own
        # transcript yet, and may never: the run is ending. It is redacted
        # and removed here, so no exit leaves a clear-text one behind.
        sweep_snapshot_transcripts(snapshot_root, secrets)
        if session_log:
            write_session_log(snapshot_root, finished)
        logging.getLogger("netstate").removeHandler(handler)
        handler.close()

    return manifest


# How many more interrupts the run waits through, after the one that stopped
# it, while the devices in a session finish. The next one stops the waiting.
DRAIN_PATIENCE = 1


def _drain(pool: ThreadPoolExecutor, futures: Sequence[Any], in_session: set[str]) -> None:
    """Wait for the devices still in a session to finish, through one more Ctrl-C.

    The pool used to be left by its `with` block, whose wait a second
    Ctrl-C broke out of: the manifest was then written while the worker
    threads went on collecting, and the devices they finished were on disk
    and in no device table. A second interrupt now says what is still
    running and waits again. A third stops the waiting, and leaves the
    names in `in_session` for the manifest of the run cut short, which
    lists them as still in session. The threads are not killed, which
    Python cannot do: a session left open on a device is worse than a wait.
    """
    patience = DRAIN_PATIENCE
    while True:
        try:
            wait(futures)
            break
        except KeyboardInterrupt:
            running = ", ".join(sorted(in_session)) or "none"
            if patience <= 0:
                log.error(
                    "stopped waiting for the device(s) still in a session (%s); the manifest "
                    "names them as not collected", running,
                )
                pool.shutdown(wait=False, cancel_futures=True)
                return
            patience -= 1
            log.warning(
                "waiting for the device(s) still in a session to finish (%s), so their "
                "transcripts are redacted and their answers kept; Ctrl-C once more stops waiting",
                running,
            )
    pool.shutdown(wait=True)


@contextlib.contextmanager
def _hangup_as_interrupt():
    """SIGHUP and SIGTERM end the run the way Ctrl-C does.

    Left to their default they end the process on the spot, and nothing a run
    collected is written down. As an interrupt they unwind like Ctrl-C, so the
    devices that finished get their manifest. Only the main thread can set a
    handler, and Windows has no SIGHUP; either way the defaults stand.
    """
    previous: dict[int, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for name in ("SIGHUP", "SIGTERM"):
            number = getattr(signal, name, None)
            if number is not None:
                previous[number] = signal.signal(number, signal.default_int_handler)
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _keep_interrupted_run(
    exc: BaseException, finished: list[DeviceResult], snapshot_root: Path, started: datetime,
    testbed_path: Path | str, policy: CommandPolicy, selected: list[str], *settings: Any,
    in_session: Sequence[str] = (),
    connection_policy: dict[str, Any] | None = None,
) -> None:
    """Write the manifest of a run that stopped before its end, for the devices that finished.

    What they answered is as good as in any finished run, so it is kept. The
    manifest says the run was cut short, why, and which devices it never
    finished, so the gap list names them. It goes into no estate database:
    a run cut short is not the estate's newest reading on its own say.

    ``in_session`` are the devices the run stopped waiting for while they
    were still being collected (see :func:`_drain`). They are among the
    devices never finished, and are named apart: what they write after this
    is on disk and in no device table of this manifest.
    """
    names = {result.name for result in finished}
    # A crawl wave is in `selected` before it starts; a device that finished
    # without being in it, or one still in session, is requested all the same.
    requested = list(selected) + [result.name for result in finished if result.name not in selected]
    requested += [name for name in in_session if name not in requested]
    # Stamped here, after the drain: the run ends when it stops waiting for
    # the devices in a session, not when the interrupt arrived.
    manifest = _build_manifest(
        snapshot_root, started, testbed_path, policy, requested, finished, *settings,
        finished_at=datetime.now(timezone.utc),
    )
    reason = (
        "interrupted (Ctrl-C or a signal)" if isinstance(exc, KeyboardInterrupt)
        else f"stopped by an error ({summarise_error(exc)})"
    )
    manifest["interrupted"] = {
        "reason": reason,
        "not_collected": [name for name in requested if name not in names],
    }
    still = [name for name in in_session if name not in names]
    if still:
        manifest["interrupted"]["in_session"] = still
    if connection_policy is not None:
        manifest["connection_policy"] = connection_policy
    try:
        _write_json(snapshot_root / "manifest.json", manifest)
    except OSError as error:
        log.error("could not write the manifest of the interrupted run: %s", error)
        return
    log.warning(
        "collection %s: %d of %d device(s) finished; the manifest keeps them, and the run "
        "is not in the estate database", reason, len(finished), len(requested),
    )


def _credential_sets_of(testbed_path: Path | str) -> dict[str, str]:
    """Which credential set each device block names, by device.

    From the testbed text rather than the loaded testbed: pyATS hands over the
    resolved values, and a value must never reach the manifest. A device with
    no block of its own — a crawled switch — is not in the map.
    """
    try:
        return credential_sets(Path(testbed_path).read_text(encoding="utf-8"))
    except OSError:
        log.debug("could not read %s for the credential sets", testbed_path, exc_info=True)
        return {}


def _disabled_devices_of(testbed_path: Path | str) -> dict[str, str]:
    """The devices finalize commented out of the testbed, with their addresses."""
    try:
        return disabled_devices(Path(testbed_path).read_text(encoding="utf-8"))
    except OSError:
        log.debug("could not read %s for its disabled devices", testbed_path, exc_info=True)
        return {}


def _annotate_credential_sets(results: Iterable[DeviceResult], testbed_path: Path | str) -> None:
    """Record the credential set on results collected without one."""
    sets = _credential_sets_of(testbed_path)
    for result in results:
        if result.credential_set is None:
            result.credential_set = sets.get(result.name)


def _connection_ip(device) -> str:
    """The address the testbed reaches a device at, or ""."""
    try:
        values = device.connections.values()
    except AttributeError:
        return ""
    for connection in values:
        ip = connection.get("ip") if hasattr(connection, "get") else getattr(connection, "ip", None)
        if ip:
            return str(ip)
    return ""


def _cli_connection(device) -> Any:
    try:
        connections = device.connections
    except AttributeError:
        return None
    if hasattr(connections, "get"):
        return connections.get("cli") or next(iter(connections.values()), None)
    return None


class CrawlRefused(CollectionError):
    """A crawled device that cannot be reached the way the device that named it is."""


def _standalone(address: str) -> re.Pattern[str]:
    """An address as a word of its own: `10.1.0.1` is not inside `10.1.0.100`."""
    return re.compile(rf"(?<![0-9A-Za-z.:]){re.escape(address)}(?![0-9A-Za-z.:])", re.IGNORECASE)


def crawled_device(testbed, candidate: "Candidate", via) -> Any:
    """A pyATS device for a crawled address, reached the way the device that named it is.

    The proxy is the reporting device's: a switch a router named is behind
    the same jump host as the router. An explicit proxy command carries the
    router's address in it and is rewritten to the switch's. The login
    quirks — the second enable, the legacy ssh options — are copied only
    where the two run the same OS, because that is how they are true.

    Raises :class:`CrawlRefused` where the last hop's command, the one that
    reaches the device, does not name the router's address on its own:
    unchanged, it would log in to the router, which would then be collected
    as the switch.
    """
    from pyats.topology import Device  # imported late: heavy dependency

    via_cli = _cli_connection(via)
    via_ip = _connection_ip(via)
    connection: dict[str, Any] = {"protocol": "ssh", "ip": candidate.address}
    proxy = via_cli.get("proxy") if via_cli is not None and hasattr(via_cli, "get") else None
    if proxy:
        if isinstance(proxy, (list, tuple)):
            rewritten = []
            # Whether the hop that reaches the device was pointed at it: one
            # with no command is, by the device's own address; one with a
            # command is when the router's address was replaced in it.
            reaches = True
            for hop in proxy:
                if hasattr(hop, "get") and hop.get("command"):
                    command, count = (
                        _standalone(via_ip).subn(candidate.address, str(hop["command"])) if via_ip
                        else (str(hop["command"]), 0)
                    )
                    rewritten.append({**dict(hop), "command": command})
                    reaches = count > 0
                else:
                    rewritten.append(hop)
                    reaches = True
            if not reaches:
                raise CrawlRefused(
                    f"the proxy command that reaches {via.name} does not name its address on "
                    f"its own, so it cannot be pointed at this device"
                )
            connection["proxy"] = rewritten
        else:
            connection["proxy"] = proxy
    same_os = str(getattr(via, "os", "") or "").lower() == candidate.os
    if same_os and via_cli is not None and hasattr(via_cli, "get") and via_cli.get("ssh_options"):
        connection["ssh_options"] = via_cli.get("ssh_options")
    custom: dict[str, Any] = {}
    if same_os and wants_double_enable(via):
        custom["double_enable"] = True
    device = Device(
        candidate.placeholder, os=candidate.os, type="router",
        connections={"cli": connection}, custom=custom,
    )
    testbed.add_device(device)
    return device


def _crawl(
    testbed, policy, snapshot_root, started, testbed_path, results, selected, logins, gates,
    chosen, skipped, connect_timeout, command_timeout, verify_reachability, mode,
    double_enable, demo, record: CrawlRecord, fence, collect_wave, factory,
) -> None:
    """Visit the switches the collected devices named, wave by wave, inside the fence."""
    known_addresses = {ip for ip in (_connection_ip(d) for d in testbed.devices.values()) if ip}
    known_names = {hostname_key(name) for name in testbed.devices}
    # A device finalize commented out is in the testbed too, though pyATS
    # never loads it: visited again, it would be appended live beside its
    # own disabled block.
    for name, address in _disabled_devices_of(testbed_path).items():
        known_names.add(hostname_key(name))
        if address:
            known_addresses.add(address)
    sources = [r.name for r in results if r.connected]
    for depth in range(1, record.depth + 1):
        if not sources:
            break
        # The snapshot as it stands, so the neighbours are read the way the
        # topology will read them, under the names the devices gave.
        reading = Snapshot(snapshot_root, _build_manifest(
            snapshot_root, started, testbed_path, policy, selected, results,
            connect_timeout, command_timeout, verify_reachability, chosen, skipped,
            mode, double_enable, demo,
        ))
        known_names |= {hostname_key(name) for name in reading.devices}
        found: list[Candidate] = []
        for learned, entry in sorted(reading.devices.items()):
            if reading.testbed_name(learned) not in sources:
                continue
            found.extend(candidates_from(
                learned, reading.state, CDP_COMMAND, LLDP_COMMANDS, depth, reading.raw, known_names,
            ))
        room = record.limit - len(record.visited)
        wave, refused = plan_wave(found, fence, known_addresses, known_names, room)
        for r in refused:
            record.decline(r.name, r.address, r.reason, r.via, depth)
        if not wave:
            break
        names: list[str] = []
        visiting: list[Candidate] = []
        for candidate in wave:
            via = testbed.devices[reading.testbed_name(candidate.via)]
            try:
                device = factory(testbed, candidate, via)
            except CrawlRefused as refusal:
                record.decline(
                    candidate.name or candidate.address, candidate.address, str(refusal), candidate.via, depth,
                )
                log.warning(
                    "crawl: %s (%s) not visited: %s",
                    candidate.name or candidate.placeholder, candidate.address, refusal,
                )
                continue
            visiting.append(candidate)
            record.withdraw(candidate.address)
            known_addresses.add(candidate.address)
            if candidate.name:
                known_names.add(hostname_key(candidate.name))
            logins[device.name] = login_prompts(device, testbed)
            key = proxy_names(device)
            if key and key not in gates:
                gates[key] = threading.Lock()
            names.append(device.name)
            log.info(
                "crawl: %s (%s, %s) named by %s on %s — visiting at hop %d",
                candidate.name or candidate.placeholder, candidate.address, candidate.os,
                candidate.via, candidate.via_interface, depth,
            )
        if not names:
            break
        visits = dict(zip(names, visiting))
        arrived: dict[str, dict[str, Any]] = {}

        def visited(result: DeviceResult) -> None:
            candidate = visits[result.name]
            arrived[result.name] = {
                "name": result.name, "reported_as": candidate.name, "address": candidate.address,
                "os": candidate.os, "via": candidate.via, "via_interface": candidate.via_interface,
                "depth": depth, "connected": result.connected,
                "proxy": _proxy_record(testbed.devices[result.name]),
                "custom": dict(getattr(testbed.devices[result.name], "custom", {}) or {}),
            }

        # Each visit is recorded as its device finishes, not once the wave
        # returns: a wave the interrupt cuts off never returns, and the
        # switches it finished kept their data in the manifest with no visit
        # beside it, so finalize appended no block for them. Wave order, either way.
        # The wave is requested before it starts, for the same reason: a
        # wave larger than the workers had switches planned and not begun,
        # withdrawn from the refusals and in no visit, and the manifest of
        # the run cut short named them nowhere, so no gap said so.
        selected.extend(names)
        try:
            wave_results = collect_wave(names, visited)
        finally:
            record.visited.extend(arrived[name] for name in names if name in arrived)
        results.extend(wave_results)
        sources = [r.name for r in wave_results if r.connected]


def _proxy_record(device) -> Any:
    """The proxy as the testbed would write it, for the block appended after the run."""
    cli = _cli_connection(device)
    proxy = cli.get("proxy") if cli is not None and hasattr(cli, "get") else None
    if not proxy:
        return None
    if isinstance(proxy, (list, tuple)):
        return [dict(hop) if hasattr(hop, "get") else hop for hop in proxy]
    return str(proxy)


# The neighbour protocol commands, as the crawl and the topology read them:
# the CDP detail form, then the Cisco LLDP detail form or the Junos brief
# table, whichever the device answered.
CDP_COMMAND = "show cdp neighbors detail"
LLDP_COMMANDS = ("show lldp neighbors detail", "show lldp neighbors")


# The name a device wears before it has given its hostname: `dev_` and its
# address with the dots (or colons) made underscores, as testbedgen writes it.
PLACEHOLDER_NAME = re.compile(r"^dev_[0-9A-Fa-f_]+$")
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")
# Device text is untrusted input. A terminal escape in a platform string or a
# neighbour name is the device's problem until it reaches an XML writer, a
# Rich table or a file name; then it is ours. Stripped once, where the text
# enters, so no writer has to know.
#
# Every escape goes whole, or what is left of it stands in front of the line
# where no rule anchored at the line's start reads it: `ESC ( B` left `(B`
# before `snmp-server community X RO`, and the community was kept. So an
# operating-system command (a window title, `ESC ] 0;R1 BEL`), or any other
# string an escape opens, runs to its terminator, BEL or ST, or to the end of
# the line where it has none; a control sequence opens with `ESC [` or with
# the one-byte C1 CSI, 0x9b; and any other escape is one of the two-byte
# escapes terminals send (`ESC 7`, `ESC =`, `ESC M`, `ESC c`, ST), a
# charset designator and its one byte (`ESC ( B`, `ESC ) 0`) or a line
# attribute (`ESC # 8`). An ESC that opens none of them goes alone: read as
# ESC and whatever byte follows, a stray one took the line's first letter
# with it, `ESC snmp-server community X RO` became `nmp-server community X
# RO`, and the community was kept. A reset, `ESC c`, is not read in front of
# the rest of a keyword the rules read (`community`, `cak`), which it would
# cut the same way.
_ANSI_SEQUENCE = re.compile(
    r"(?:\x1b[\]PX^_]|[\x90\x98\x9d-\x9f])[^\x07\x1b\x9c\n]*(?:\x07|\x1b\\|\x9c)?"
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
    r"|\x1b(?:[()*+\-./][0-~]|#\d|[78=>DEHMNOZ\\]|c(?!(?:ommunity|ak)\b))"
)
# Characters that print as nothing: the control characters (Unicode category
# Cc, the C1 ones from 0x80 to 0x9f with them) but the tab, the newline and
# the carriage return, and every format character (Cf): a zero-width space,
# joiner or mark, a soft hyphen, a byte-order mark, a bidi isolate, a tag.
# Pasted into a configuration with it, one in front of `snmp-server
# community X`, or inside its keyword, hid the line from every rule. A list
# of them left out the ones nobody had thought of, so the category decides,
# as the Python running DiscoNet knows it; only a character outside printable
# ASCII is looked up, so text with none costs one scan.
_UNPRINTED_CANDIDATE = re.compile(r"[^\t\n\r -~]")


def _printed(found: re.Match[str]) -> str:
    """The character found, or nothing where it is a control or a format character."""
    return "" if unicodedata.category(found.group()) in ("Cc", "Cf") else found.group()
# A device that pages its output after all (command authorization refused
# `terminal length 0`) prints its prompt at the start of a line, ` --More-- `,
# `<--- More --->` or Junos's `---(more 42%)---`, and erases it on the
# terminal with backspaces, spaces and backspaces again, or with a carriage
# return. In the text the prompt stays in front of the line it was erased
# for, where no rule anchored at the line's start reads that line. Only a
# prompt something erases is one, and the erasing ends on its last
# backspace, so the indentation of the line after it is the line's.
#
# The prompt is often drawn in reverse video, `ESC [7m --More-- ESC [27m`,
# whose escapes hid it from this rule when it ran first, and an escape
# (`ESC [8D ESC [K`) is one of the ways it is erased. So the escapes are
# read first, each left as a lone ESC: the rule reads past those around the
# prompt and takes one after it as its erasing, and the lone ESCs go with the
# other control characters.
_PAGER_PROMPT = re.compile(
    r"^[ \t\x1b]*(?:<-+[ \t]*more[ \t]*-+>|-+[ \t]*\(?more(?:[ \t]+\d+%)?\)?[ \t]*-+)[ \t\x1b]*(?=[\x08\r\x1b])"
    r"(?:[\x08 \x1b]*\x08)?",
    re.IGNORECASE | re.MULTILINE,
)


def clean_text(text: str) -> str:
    """Device output with terminal escapes, pager prompts, control and invisible characters removed.

    Tabs, newlines and carriage returns stay: they are layout, and the parsers
    read them. Every other control character, and every character that
    prints as nothing, has no place in a document, an SVG or a file name.
    The escapes go first, so a C1 control that opens one (0x9b, 0x9d) takes
    its sequence with it rather than going alone.
    """
    return _UNPRINTED_CANDIDATE.sub(_printed, _PAGER_PROMPT.sub("", _ANSI_SEQUENCE.sub("\x1b", text)))


def clean_strings(value: Any) -> Any:
    """``clean_text`` applied to every string inside a parsed structure."""
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, dict):
        return {clean_strings(key): clean_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean_strings(item) for item in value]
    return value
# A name made only of dots is a path component, not a hostname.
_DOTS_ONLY = re.compile(r"^\.+$")


def learned_hostname(snapshot: "Snapshot", device: str) -> str:
    """The name the device calls itself, from its own output, or "".

    The running configuration first, then the parsed `show version`, and on
    Junos `show version` first, then the `system` host-name: the reading
    `disconet finalize` renames the testbed by, called rather than copied,
    so the snapshot and the testbed agree on what a device is called. The
    first `host-name` of a Junos configuration is not the box's: a dual-RE
    box names each routing engine under `groups`, printed before `system`,
    and was documented as re0 whichever engine answered.
    """
    return _hostname_from(snapshot, device, str(snapshot.devices.get(device, {}).get("os") or ""))


def learned_names(snapshot: "Snapshot") -> dict[str, str]:
    """`placeholder testbed name -> the hostname the device gave`, for the devices that gave one.

    A device pointed at by address alone is called `dev_10_0_0_1` until it
    answers. Once it has, every table, diagram and sentence should call it
    what it calls itself — in the snapshot that learned it, not only in the
    next one. A hostname that another device already wears, or that cleans
    to nothing, leaves the placeholder in place.
    """
    raw = snapshot.manifest.get("devices", {}) or {}
    taken = set(raw)
    names: dict[str, str] = {}
    for name, entry in raw.items():
        if not PLACEHOLDER_NAME.match(name) or entry.get("testbed_name"):
            continue
        if not snapshot.produced_data(name):
            continue
        wanted = _UNSAFE_NAME.sub("_", learned_hostname(snapshot, name).strip()).strip("_")
        if _DOTS_ONLY.match(wanted):
            wanted = ""
        if wanted and wanted != name and wanted not in taken:
            names[name] = wanted
            taken.add(wanted)
    return names


@dataclass
class Snapshot:
    """A collected snapshot on disk, read back for the later phases.

    Everything downstream — topology, document generation, factcheck — reads
    device data through this class, so there is one definition of where a fact
    came from.

    Devices are keyed by the name the device gave, where it gave one: a
    placeholder the testbed pointed at by address is called by its hostname
    from the moment the snapshot is read, and `testbed_name` on the entry
    says what the testbed, the files and the database call it.
    """

    root: Path
    manifest: dict[str, Any]
    # An open connection to the estate database, when this run is in one. Every
    # read below prefers it and falls back to the files, so a snapshot taken
    # before the database existed, or one whose database is missing, reads
    # exactly as it always did. Nothing downstream can tell the difference,
    # which is the point: one storage change, not fifteen call sites.
    db: Any = None
    _names: dict[str, str] | None = field(default=None, repr=False, compare=False)
    _named: dict[str, dict[str, Any]] | None = field(default=None, repr=False, compare=False)
    # The link-state domains last read from this snapshot, with the topology
    # they were read against. See disconet.lsdb.link_state_domains.
    _link_state: tuple[Any, str, list[Any]] | None = field(default=None, repr=False, compare=False)

    @classmethod
    def load(cls, root: Path | str, db: Path | str | None = None) -> "Snapshot":
        # Resolved, so that `.` or a bare id has the parent the database sits in.
        root = Path(root).resolve()
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file():
            raise CollectionError(
                f"{root} is not a DiscoNet snapshot (no manifest.json). "
                f"Point --snapshot at a directory created by `disconet collect`."
            )
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CollectionError(f"{manifest_path} is not valid JSON: {exc}") from exc
        snapshot = cls(root=root, manifest=clean_strings(manifest))
        where = db if db is not None else store.default_path(root.parent)
        if not snapshot.attach(where) and store.files_pruned(root, manifest):
            # The silent fallback to the files has nothing to fall back to: a
            # run collected with --db-only kept its device output only in the
            # database. Read on, and every table comes out [NOT COLLECTED], a
            # document of a network that answered nothing rather than an error.
            raise CollectionError(
                f"{root} holds no device output of its own: its files were pruned "
                f"after ingest (--db-only), and {where} is missing or does not hold this run. "
                f"Point --db at the estate database it was collected into; "
                f"`disconet db list --db PATH` shows the runs a database holds."
            )
        return snapshot

    @classmethod
    def from_db(
        cls, db: Path | str, snapshot_id: str, root: Path | str | None = None
    ) -> "Snapshot":
        """Read a run out of the estate database, files or no files.

        ``root`` still matters even when nothing is read from it: `topology` and
        `generate` write their output into the snapshot directory. It defaults
        to the directory the run was collected into, which is recorded at ingest.
        """
        # Read-only, and only a file that exists: a mistyped --db must say so,
        # not create an empty estate database at the wrong path.
        if not Path(db).is_file():
            raise CollectionError(
                f"there is no estate database at {db}. `disconet db list` shows "
                f"the runs the estate's database holds."
            )
        try:
            connection = store.open_existing(db)
            manifest = store.manifest_of(connection, snapshot_id)
        except sqlite3.Error as exc:
            raise CollectionError(f"{db} is not an estate database: {exc}") from exc
        if manifest is None:
            connection.close()
            raise CollectionError(
                f"the estate database at {db} holds no run called '{snapshot_id}'. "
                f"`disconet db list` shows the ones it does have."
            )
        if root is None:
            # Read as `db forget` reads it: an older ingest's relative root
            # is found against the database's directory, not the current one.
            root = store.recorded_root(connection, snapshot_id) or snapshot_id
        return cls(root=Path(root), manifest=clean_strings(manifest), db=connection)

    def attach(self, db: Path | str | None) -> bool:
        """Point this snapshot at an estate database, if it holds this run.

        A database that does not exist, cannot be opened, or does not carry this
        run leaves the snapshot reading from files. That is a silent fallback on
        purpose: the files are the same data, and a warning on every read would
        train the reader to ignore warnings.
        """
        self.db = None
        if db is None:
            return False
        path = Path(db)
        if not path.is_file():
            return False
        try:
            # Read-only: attaching is a read, and a read should not need write
            # access to a shared database or to a snapshot on a mounted archive.
            connection = store.open_existing(path)
            if not store.has_snapshot(connection, self.snapshot_id):
                connection.close()
                return False
        except sqlite3.Error:
            log.debug("estate database at %s could not be opened", path, exc_info=True)
            return False
        self.db = connection
        return True

    def close(self) -> None:
        """Let go of the estate database. Reads after this come from the files.

        An open reader stops SQLite folding its write-ahead log into the
        database file when the writer closes, so a run stored while a
        snapshot was still open could be left in disconet.db-wal alone.
        """
        if self.db is not None:
            self.db.close()
            self.db = None

    def _row(self, device: str, command: str) -> Any:
        if self.db is None:
            return None
        try:
            return store.output(self.db, self.snapshot_id, self.testbed_name(device), command)
        except sqlite3.Error:  # noqa: BLE001 - fall through to the files
            log.debug("estate database read failed", exc_info=True)
            return None

    @property
    def snapshot_id(self) -> str:
        return str(self.manifest.get("snapshot_id", self.root.name))

    @property
    def created_at(self) -> str:
        return str(self.manifest.get("created_at", ""))

    @property
    def devices(self) -> dict[str, dict[str, Any]]:
        raw = self.manifest.get("devices", {}) or {}
        if self._names is None:
            # Learning the names reads the snapshot through this very
            # property, under the testbed names; an empty map during the
            # build is what makes those reads plain.
            self._names = {}
            self._names = learned_names(self)
            self._named = None
        if not self._names:
            return raw
        if self._named is None:
            self._named = {
                self._names.get(name, name): (
                    {**entry, "testbed_name": name} if name in self._names else entry
                )
                for name, entry in raw.items()
            }
        return self._named

    def testbed_name(self, device: str) -> str:
        """What the testbed, the files and the database call this device."""
        entry = self.devices.get(device) or {}
        return str(entry.get("testbed_name") or device)

    def read_by(self, device: str) -> tuple[str, str]:
        """The run that read this device and when it began, as `(snapshot_id, created_at)`.

        A run's own for a run. A merge carries its newest source's created_at,
        and a device taken from an earlier run was read then, so the merge
        records that run in `device_sources` and its date in `device_read_at`.
        Both name the run that actually read the device, however many merges
        it was carried through: each merge resolves its sources' devices with
        this, so a merge of merges keeps the original read rather than the
        merge in between. A merge written before `device_read_at` existed has
        its sources dated in `merged_from`, which is read instead.
        """
        source, when = store.merged_read_by(self.manifest, (device, self.testbed_name(device)))
        if not source:
            return self.snapshot_id, self.created_at
        return source, when or self.created_at

    def learned_from(self, testbed_name: str) -> str:
        """The name a testbed placeholder is documented under, or the placeholder itself."""
        self.devices  # noqa: B018 - learn the names first
        return (self._names or {}).get(testbed_name, testbed_name)

    @property
    def features(self) -> tuple[str, ...]:
        """Protocol and service groups this snapshot was collected for.

        A snapshot taken before feature selection existed carries no such key;
        it was collected with everything, so that is what it reports.
        """
        recorded = self.manifest.get("features")
        if recorded is None:
            return ALL_FEATURES
        return tuple(str(key) for key in recorded)

    @property
    def features_skipped(self) -> tuple[str, ...]:
        return tuple(str(key) for key in self.manifest.get("features_skipped") or ())

    @property
    def mode(self) -> str:
        """The discovery mode asked for at collection time.

        A snapshot taken before the question existed answers `loose`, which is
        what it was collected under: every reading before this was that one.
        """
        recorded = str(self.manifest.get("mode") or "").strip().lower()
        return recorded if recorded in DISCOVERY_MODES else DEFAULT_DISCOVERY_MODE

    @property
    def demo(self) -> bool:
        """Was the discovery animation asked for when this was collected?

        Off for any snapshot that does not say otherwise, which includes every
        snapshot taken before the question existed. A demo is something an
        operator opts into, so silence means no.
        """
        return bool(self.manifest.get("demo"))

    @property
    def synthetic(self) -> bool:
        """Was this written by the synthetic demonstration estate rather than collected?

        Only `true` itself counts. A real run never writes the field, so its
        absence, or any other value, is a collected network: a document must
        never be marked fictional because a manifest carried a stray string.
        """
        return self.manifest.get("synthetic") is True

    @property
    def synthetic_notice(self) -> str:
        """What the synthetic estate says about itself; "" for a collected network."""
        return str(self.manifest.get("synthetic_notice") or "").strip() if self.synthetic else ""

    def collected_feature(self, key: str) -> bool:
        return key in self.features

    # Statuses that mean the device answered: the output reached disk, whether
    # or not Genie could make a structure out of it.
    ANSWERED = frozenset({"parsed", "empty", "unparsed", "raw"})

    def answered_not_running(self, device: str, command: str) -> bool:
        """Did the device answer that the protocol this command shows is not running?

        `% BGP not active` is how IOS and IOS-XE answer a BGP summary with no
        `router bgp` configured. Where Genie has a parser it makes that an
        empty parse, which is a reading; classic IOS has none for the
        summary, so the same answer came back unparsed, was listed as a
        collection gap and left the device's BGP unknown. It is a reading
        there too: the device said it runs no BGP.
        """
        return self.status(device, command) in self.ANSWERED and says_not_running(self.raw(device, command) or "")

    def produced_data(self, device: str) -> bool:
        """Did this device answer anything at all?

        Connecting is not collecting. A session that opens and then loses its
        state machine leaves a device that is `connected: true` with not one
        usable command, and calling that collected puts a falsehood in the
        document — the count of collected devices is a documented fact.
        """
        entry = self.devices.get(device, {})
        if not entry.get("connected"):
            return False
        return any(
            command.get("status") in self.ANSWERED
            for command in entry.get("commands", [])
            if not str(command.get("command", "")).startswith("ping ")
        )

    @property
    def device_names(self) -> list[str]:
        """Devices that were reached and answered, in testbed order."""
        return [name for name in self.devices if self.produced_data(name)]

    def _entry(self, device: str, command: str) -> dict[str, Any] | None:
        wanted = CommandPolicy.normalise(command)
        matches = [
            entry
            for entry in self.devices.get(device, {}).get("commands", [])
            if CommandPolicy.normalise(entry.get("command", "")) == wanted
        ]
        # A VRF name keeps its case: `show ip arp vrf Mgmt` and `show ip arp
        # vrf MGMT` are two tables, and lowercased they are one, the first.
        # The command as the manifest spells it wins; the lowercase match is
        # for a caller that spells it the allowlist's way.
        for entry in matches:
            if entry.get("command") == command:
                return entry
        return matches[0] if matches else None

    def commands(self, device: str) -> list[str]:
        """Every command this device was sent, as the manifest spells it.

        The per-VRF tables are rendered at collection time, one command per
        VRF, so a reader that wants every ARP table has to ask what was
        sent rather than what the allowlist lists.
        """
        return [
            str(entry.get("command", ""))
            for entry in self.devices.get(device, {}).get("commands", [])
            if entry.get("command")
        ]

    def status(self, device: str, command: str) -> str | None:
        """How this command turned out: parsed, empty, unparsed, raw, failed."""
        entry = self._entry(device, command)
        return entry.get("status") if entry else None

    def state(self, device: str, command: str) -> dict[str, Any] | None:
        """Genie-parsed state, or None if this command was not parsed."""
        entry = self._entry(device, command)
        if not entry:
            return None
        row = self._row(device, str(entry.get("command", "")))
        if row is not None and row["state"] is not None:
            try:
                return clean_strings(json.loads(row["state"]))
            except json.JSONDecodeError:
                log.warning("%s: stored state for %s is not valid JSON", device, command)
                return None
        if not entry.get("state_file"):
            return None
        path = self.root / entry["state_file"]
        if not path.is_file():
            return None
        try:
            return clean_strings(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            log.warning("%s: %s is not valid JSON", device, path)
            return None

    def raw(self, device: str, command: str) -> str | None:
        """Redacted raw output, or None if nothing was captured.

        Unparsed output is read from the database the same way parsed state is.
        It is the output most likely to be wanted months later — a command with
        no Genie schema on the platform that actually matters — so it would be
        the worst thing to leave outside the queryable store.
        """
        entry = self._entry(device, command)
        if not entry:
            return None
        row = self._row(device, str(entry.get("command", "")))
        if row is not None and row["raw"] is not None:
            return clean_text(str(row["raw"]))
        if not entry.get("raw_file"):
            return None
        path = self.root / entry["raw_file"]
        return clean_text(path.read_text(encoding="utf-8")) if path.is_file() else None

    def config(self, device: str) -> str:
        """The device's running configuration, redacted, or "" if never captured.

        `show running-config` on the Cisco platforms, `show configuration` on
        Junos: the platform says which, so nothing else has to.
        """
        platform = platforms.platform_for(self.devices.get(device, {}).get("os"))
        command = platform.config_command if platform else "show running-config"
        return self.raw(device, command) or ""

    def probe_results(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Reachability probe outcomes, keyed by device then target address.

        Empty unless the snapshot was collected with ``--verify-reachability``.
        """
        outcomes: dict[str, dict[str, dict[str, Any]]] = {}
        for name, device in self.devices.items():
            for entry in device.get("commands", []):
                command = str(entry.get("command", ""))
                if not command.startswith("ping "):
                    continue
                address = command.split(" ", 1)[1].strip()
                # One spelling, the one a reader compares against: IOS-XE
                # prints IPv6 upper-case, and a key in another case is a
                # link that reads 'not probed'.
                with contextlib.suppress(ValueError):
                    address = str(ipaddress.ip_address(address))
                statistics: dict[str, Any] = {}
                state = self.state(name, command) or {}
                statistics = (state.get("ping") or {}).get("statistics") or {}
                rate = statistics.get("success_rate_percent")
                outcomes.setdefault(name, {})[address] = {
                    "success_rate_percent": rate,
                    "sent": statistics.get("send"),
                    "received": statistics.get("received"),
                    "reachable": bool(rate is not None and rate > 0),
                    "status": entry.get("status"),
                }
        return outcomes

    # Commands DiscoNet reads from the raw text itself, because the two
    # platforms' Genie schemas disagree or because no parser exists. Genie
    # failing on these is not a collection gap: the output is on disk and was
    # read. Reporting it as one would put a warning in the document about data
    # the document is actually built from.
    TEXT_PARSED = frozenset(
        {
            "show isis neighbors",
            "show isis adjacency",
            "show isis interface brief",
            "show mpls ldp discovery",
            "show segment-routing mpls state",
            "show segment-routing mpls connected-prefix-sid-map ipv4",
            "show segment-routing local-block",
            "show isis segment-routing label table",
            "show ptp clock running domain 44",
            "show ptp clock dataset current",
            "show ptp clock dataset parent",
            "show ptp clock dataset default",
            "show ptp platform servo",
            "show ptp foreign masters",
            "show ptp foreign-masters",
            "show ptp advertised-clock",
            "show mpls traffic-eng tunnels",
            "show mpls l2transport vc detail",
            "show l2vpn xconnect detail",
            "show l2vpn service all",
            "show l2vpn bridge-domain",
            "show vrf detail",
            "show vrf all detail",
            "show ip pim rp mapping",
            "show pim group-map",
            "show mrib route summary",
            "show ip pim mdt",
            "show ip pim mdt bgp",
            "show pim vrf all mdt cache",
            "show pim vrf all neighbor",
            "show bgp ipv4 mvpn all",
            "show bgp ipv4 mvpn",
            "show mpls mldp database",
            "show isis interface",
            "show route instance detail",
        }
    )

    # Spellings of one command that differ between releases. A device is
    # sent every spelling and rejects all but the one it has, so a rejected
    # spelling is no gap where another spelling of it answered.
    ALIASES = (frozenset({"show ptp foreign masters", "show ptp foreign-masters"}),)

    def _text_parsed_for(self, device: str) -> frozenset[str]:
        """Commands this device's platform reads from text whatever Genie does."""
        platform = platforms.platform_for(self.devices.get(device, {}).get("os"))
        return frozenset(CommandPolicy.normalise(c) for c in (platform.text_parsed if platform else ()))

    def gaps(self) -> list[str]:
        """Human-readable list of everything that did not come back parsed.

        This is what the generated document must honestly report as
        `[NOT COLLECTED]` rather than guess at. Reachability probes are
        excluded: an unanswered ping is a finding, not a collection gap.
        """
        gaps: list[str] = []
        unsupported: dict[str, list[str]] = {}
        in_ptp: set[str] = set()
        for name, device in sorted(self.devices.items()):
            if not device.get("connected"):
                gaps.append(f"{name}: not reached ({device.get('error') or 'unknown error'})")
                continue
            if not self.produced_data(name):
                # A session that opens and then loses its state machine fails
                # every command with the same message. One line says it; twenty
                # identical ones bury everything else.
                reasons = [
                    str(command.get("detail") or command.get("status"))
                    for command in device.get("commands", [])
                ]
                reason = device.get("error") or (reasons[0] if reasons else "no commands were attempted")
                gaps.append(
                    f"{name}: connected but answered nothing — "
                    f"every command failed ({reason})"
                )
                continue
            # A device that logged in keeps an error only when a defect
            # stopped its collection, and that is why the commands after it
            # are missing: said once, beside them.
            if device.get("error"):
                gaps.append(f"{name}: {device['error']}")
            answered = {
                CommandPolicy.normalise(entry.get("command", ""))
                for entry in device.get("commands", [])
                if entry.get("status") in self.ANSWERED
            }
            if any(command.startswith("show ptp") for command in answered):
                in_ptp.add(name)
            for entry in device.get("commands", []):
                if str(entry.get("command", "")).startswith("ping "):
                    continue
                status = entry.get("status")
                command = CommandPolicy.normalise(entry.get("command", ""))
                # A command the platform does not have says the same thing on
                # every device that lacks it, so it is reported once rather
                # than ten times: whole-fleet noise buries the real failures.
                if status == "unsupported":
                    if any(command in spellings and answered & spellings for spellings in self.ALIASES):
                        continue
                    unsupported.setdefault(entry["command"], []).append(name)
                elif status == "unparsed" and (
                    CommandPolicy.normalise(entry.get("command", "")) in self.TEXT_PARSED
                    or CommandPolicy.normalise(entry.get("command", "")) in self._text_parsed_for(name)
                    or self.answered_not_running(name, str(entry.get("command", "")))
                ):
                    continue
                elif status in ("unparsed", "failed"):
                    gaps.append(
                        f"{name}: {entry['command']} {status}"
                        + (f" ({entry['detail']})" if entry.get("detail") else "")
                    )
            # Counted, not named: a name the rendering refused is one the rest
            # of the tool may not know for a VRF either, and this line reaches
            # the document. The manifest names them.
            reasons: dict[str, int] = {}
            for reason in (device.get("vrfs_not_read") or {}).values():
                reasons[str(reason)] = reasons.get(str(reason), 0) + 1
            for reason, count in sorted(reasons.items()):
                gaps.append(f"{name}: the per-VRF tables of {count} VRF(s) not read — {reason}")
        for command, devices in sorted(unsupported.items()):
            # A device that answered no PTP command at all is not a hole in the
            # collection: it is a device outside the PTP domain. Which is not
            # the same as a device that cannot do PTP, and the gap list does
            # not speculate about which of the two it is. A device that did
            # answer one is in the domain, and lacks only this command.
            outside = [d for d in devices if d not in in_ptp] if command.startswith("show ptp") else []
            if outside:
                gaps.append(
                    f"{command}: not recognised on {len(outside)} device(s) "
                    f"({', '.join(outside)}) — those devices do not participate in PTP"
                )
            lacking = [d for d in devices if d not in outside]
            if lacking:
                gaps.append(
                    f"{command}: not supported on {len(lacking)} device(s) "
                    f"({', '.join(lacking)})"
                )
        # A run cut short says which devices it never finished. Read against
        # the devices held, under either name, so a merge that later collected
        # one does not name it.
        held = set(self.devices) | {self.testbed_name(name) for name in self.devices}
        interrupted = self.manifest.get("interrupted") or {}
        unfinished = [
            str(name) for name in interrupted.get("not_collected") or [] if str(name) not in held
        ]
        # The ones the run stopped waiting for in the middle of their session
        # are named apart: their output may be on disk, and is not read.
        running = {str(name) for name in interrupted.get("in_session") or []}
        waited = [name for name in unfinished if name not in running]
        if waited:
            gaps.append(
                f"{', '.join(waited)}: not collected — the run was "
                f"{interrupted.get('reason') or 'interrupted'} before reaching the end"
            )
        stopped = [name for name in unfinished if name in running]
        if stopped:
            gaps.append(
                f"{', '.join(stopped)}: still in session when the run, "
                f"{interrupted.get('reason') or 'interrupted'}, stopped waiting for it; "
                f"not collected, and any output it left on disk is not read"
            )
        # A device the run was asked for and holds no entry for is a gap
        # whatever lost the mark above: without this line it would be in no
        # device table and no gap list, as if the estate did not have it.
        unaccounted = [
            str(name) for name in self.manifest.get("requested_devices") or []
            if str(name) not in held and str(name) not in unfinished
        ]
        if unaccounted:
            gaps.append(
                f"{', '.join(dict.fromkeys(unaccounted))}: not collected — the run was asked "
                f"for them and holds no record of them"
            )
        # A device in the testbed that no run behind a merge was asked for:
        # added after the whole run, it is named only by the rounds after it,
        # whose `devices_not_requested` a merge with the whole run clears. Read
        # against every name a device is held or was asked for by, and against
        # the lines above, so a device is said to be missing once. What a run
        # of part of the estate was not asked for is its selection, as a
        # deselected protocol is, and is not on this list (merge._never_collected).
        named = held | set(unfinished) | set(unaccounted) | {
            str(name) for name in self.manifest.get("requested_aliases") or {}
        }
        for name in dict.fromkeys(str(name) for name in self.manifest.get("devices_never_collected") or []):
            if name not in named:
                gaps.append(f"{name}: in the testbed, never collected by any run")
        return gaps


# A banner whose text runs on past the line that opens it: the delimiter is
# `^C` as IOS prints it, or the one punctuation character IOS-XR and NX-OS
# keep as typed. The ASA writes one `banner motd <text>` line per line of
# text and has no delimiter, which a letter after the keyword shows.
_BANNER = re.compile(r"^banner\s+[\w-]+\s+(?P<delimiter>\^C|[^\w\s])(?P<rest>.*)$")


def _banner_end(lines: list[str], start: int, *, escaped_close: bool = False) -> int | None:
    """The index of the line that closes the banner opened at `start`, or None.

    None where the line opens no banner, the banner closes on its own line,
    or the delimiter never comes back: a configuration cut short is better
    read line by line than swallowed whole into its banner. The delimiter
    closes a banner at the end of a line, which is where the platforms print
    it; one met inside a line is text, and a lone `!` is the separator
    between stanzas. So an ASA banner line whose text opens with `(` or `!`
    is closed by no later `nat (inside,outside)` or separator, and takes no
    configuration with it.

    IOS prints its `^C`, which no one types as text, alone or at the end of
    the last line of text, and either closes. A typed delimiter closes on a
    line of its own, as NX-OS prints it, and at the end of the last line of
    text, as IOS-XR and NX-OS print it as often (`Key personnel only#`),
    with two cautions, because a close found too soon is only text read as
    configuration and a close found where no banner was opened turns the
    configuration before it into text, keys and all. The device ends a
    banner at its delimiter, so its text never holds one: a line with the
    delimiter anywhere but at its end (an ACL remark of asterisks, `rack #4
    uplink#`) says no banner was opened here, and none is. And a character
    that configuration lines and sentences end with (`*` a remark, `-` a
    table's rule, `.`, `)`, a quote) closes only on a line of its own: at
    the end of other text it is that text's.

    ``escaped_close`` also closes a typed-delimiter banner on a line that is
    the delimiter and one backslash (`#\\`), as IOS-XR configurations print
    it. Only the stanza split passes it: there a close found
    in the wrong place mis-groups lines in a count. Redaction must not: a
    stray `#\\` read as a close would turn the configuration above it into
    banner text, which is redacted more lightly, keys and all.
    """
    match = _BANNER.match(lines[start].strip())
    if not match or match.group("delimiter") in match.group("rest") or _asa_output(lines):
        return None
    delimiter = match.group("delimiter")
    for index in range(start + 1, len(lines)):
        if _BANNER_LINE.match(lines[index]):
            # A banner's text never holds the next `banner` line: an ASA's
            # lines of one banner, each its own statement, are what this is.
            return None
        closing = lines[index].strip()
        if delimiter == "^C":
            if closing.endswith("^C"):
                return index
            continue
        if closing == "!":
            continue
        if closing == delimiter:
            return index
        if escaped_close and closing == delimiter + "\\":
            return index
        if delimiter in closing[:-1]:
            return None
        if closing.endswith(delimiter) and delimiter not in _ENDS_CONFIGURATION:
            return index
    return None


# The characters a line of configuration or of prose often ends with, which
# close a banner typed with them only on a line of their own (see
# _banner_end).
_ENDS_CONFIGURATION = frozenset(".,;:)]}>\"'-*/=+")


# What only an ASA prints: its version header, and the `nameif` that names
# each of its interfaces. An ASA writes one `banner motd <text>` line per line
# of text, so a line of one punctuation character there is text, never the
# opening of a banner that runs on: read as one, `banner motd *` turned the
# configuration down to the next line ending in `*` into free text, keys and
# all (C-01).
# Firepower Threat Defense writes `NGFW Version` where the ASA writes its own.
_ASA_MARK = re.compile(r"^(?:ASA Version\s|NGFW Version\s|\s*nameif\s)")


def _asa_output(lines: list[str]) -> bool:
    return any(_ASA_MARK.match(line) for line in lines)


def config_stanzas(config: str, inherit: bool = True) -> list[list[str]]:
    """Split a running configuration into top-level stanzas, by indentation.

    The first line of each stanza is what opens it — `router ospf 1`,
    `interface GigabitEthernet2` — and the indented lines under it belong to
    it. Comment separators and blank lines are dropped. A banner's text is
    the device's free text, unindented, and belongs to the banner: read as
    stanzas of their own, its lines would open families named by whatever
    words the text began with. Shared, because the configuration is the only
    place several facts are stated the same way on both platforms, and two
    readings of it would eventually disagree.

    Each line is a `ConfigLine`: the text as before, carrying its line
    number for the statement ledger (`netstate.ledger`).

    With `inherit` (the default) the stanzas are those the device runs: an
    IOS-XR `group` applied by `apply-group` is resolved first
    (`netstate.inheritance`), so an interface stanza holds what the group
    gives it, each inherited line carrying the group's own line number, and
    the group and the apply line are no stanzas. A configuration without
    groups, and every other platform's, comes back as written.
    `inherit=False` is for the stanza-level figure, which counts lines where
    they stand.
    """
    stanzas: list[list[str]] = []
    current: list[str] = []
    lines = effective_lines(config, nested=False) if inherit else numbered_lines(config)
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.startswith("!"):
            continue
        if not line.startswith((" ", "\t")):
            if current:
                stanzas.append(current)
            current = [ConfigLine(line.rstrip(), line.line_no)]
            end = _banner_end(lines, index - 1, escaped_close=True)
            if end is not None:
                current.extend(
                    ConfigLine(text.rstrip(), text.line_no)
                    for text in lines[index:end + 1] if text.strip()
                )
                index = end + 1
        elif current:
            current.append(ConfigLine(line.rstrip(), line.line_no))
    if current:
        stanzas.append(current)
    return stanzas


def _build_manifest(
    snapshot_root: Path,
    started: datetime,
    testbed_path: Path | str,
    policy: CommandPolicy,
    selected: list[str],
    results: list[DeviceResult],
    connect_timeout: int,
    command_timeout: int,
    verify_reachability: bool = False,
    features: Iterable[str] = (),
    features_skipped: Iterable[str] = (),
    mode: str = DEFAULT_DISCOVERY_MODE,
    double_enable: bool = False,
    demo: bool = False,
    crawl: "CrawlRecord | None" = None,
    estate: str = "",
    retry_of: str = "",
    not_requested: Iterable[str] = (),
    finished_at: datetime | None = None,
) -> dict[str, Any]:
    """The collection manifest of one run.

    ``finished_at`` is when the run ended, recorded in UTC whatever its zone.
    It is None for a manifest of a run still under way (the crawl reads one
    between its waves), and the key is then null: such a run has not
    finished, and nothing should read a moment as its end.
    """
    return {
        "netstate_version": __version__,
        # The pyATS, Genie and unicon releases the run connected and parsed
        # with, by distribution name (PYATS_DISTRIBUTIONS).
        "pyats_versions": pyats_versions(),
        "snapshot_id": snapshot_root.name,
        "created_at": started.isoformat(),
        # When the run ended, beside when it began. The export manifest states
        # the window the snapshot was collected in, and only the run itself
        # knows when it ended: the newest file in the directory is no measure
        # of it, since a device still in a session when a run was cut short
        # writes its files after the manifest.
        "finished_at": finished_at.astimezone(timezone.utc).isoformat() if finished_at is not None else None,
        # The collecting machine's offset from UTC at that moment, so the hour
        # a rate was sampled at is the operator's hour and not a guess made
        # later on another machine.
        "utc_offset_minutes": _utc_offset_minutes(started),
        "testbed": str(testbed_path),
        "commands_file": policy.source,
        # The SHA-256 of the allowlist bytes this run parsed, None for a policy
        # built in memory. The path above says where the allowlist was on the
        # collecting machine, and the file there can change after the run; the
        # hash is what an export, and whoever receives it, compares with the
        # allowlist they trust, so it is taken by the run that loaded it.
        "commands_sha256": policy.sha256,
        "requested_devices": selected,
        "connect_timeout": connect_timeout,
        "command_timeout": command_timeout,
        "verify_reachability": verify_reachability,
        # What the engineer asked for. A protocol that is absent from the
        # document because nobody looked for it is a different statement from
        # one that is absent because no device runs it, and only the manifest
        # can tell the two apart later.
        "features": list(features),
        "features_skipped": list(features_skipped),
        # How much a link must prove before the topology counts it. Recorded
        # rather than applied here: the collection is the same either way, and
        # this is what a later `topology` run defaults to.
        "mode": mode,
        # The estate the run was started under, empty without one. Read back by
        # `generate` and `topology` to name the deliverables after the network,
        # so a snapshot copied out of its estate directory still knows whose
        # it is.
        "estate": estate,
        # The run whose missed devices this one went back for, empty for a
        # run of its own. Such a run holds those few devices and nothing of
        # the estate around them, so it is never the run read by default.
        "retry_of": retry_of,
        # The testbed's devices a `collect --devices` run was not asked for,
        # empty for a run of the whole testbed. Like a retry round's, such a
        # run is part of the estate and never the run read by default.
        "devices_not_requested": list(not_requested),
        # Only records the run-wide override; a device that asked for the second
        # enable in the testbed says so in the testbed, which is named above.
        "double_enable": double_enable,
        # Asked at collect time and acted on much later, by `topology`. It
        # reaches no device and changes nothing that is collected: it is a
        # presentation choice, recorded here only because this is the file
        # that travels with the snapshot.
        "demo": demo,
        # What the crawl visited and what it declined, each with its reason.
        # Off, the record says so, so a snapshot never reads as one that
        # looked and found nothing.
        "crawl": crawl.as_dict() if crawl is not None else {"enabled": False},
        "devices": {result.name: result.as_dict() for result in results},
        "summary": summarise_devices({result.name: result.as_dict() for result in results}),
    }


def _utc_offset_minutes(moment: datetime) -> int:
    offset = moment.astimezone().utcoffset()
    return int(offset.total_seconds() // 60) if offset is not None else 0


def summarise_devices(devices: dict[str, Any]) -> dict[str, int]:
    """The manifest's `summary` block, counted from the device entries.

    Counted from the serialised form rather than from :class:`DeviceResult` so
    that a snapshot assembled out of other snapshots is summarised by exactly
    the same arithmetic as one that came off devices. A merged snapshot whose
    summary was carried over or added up from its sources would disagree with
    its own device entries, and the summary is where the document's collected
    counts come from.
    """
    counts: dict[str, int] = {}
    probes = 0
    probes_failed = 0
    redacted = 0
    connected = 0
    for entry in devices.values():
        if entry.get("connected"):
            connected += 1
        for command in entry.get("commands", []) or []:
            status = str(command.get("status", ""))
            redacted += int(command.get("redacted_lines") or 0)
            # A probe is counted apart from the show commands. One that could
            # not complete is a finding about the neighbour, not a hole in the
            # collection, and counted with the commands it made the run partial.
            if str(command.get("command", "")).startswith("ping "):
                probes += 1
                probes_failed += 1 if status == "failed" else 0
                continue
            counts[status] = counts.get(status, 0) + 1
    return {
        "devices_total": len(devices),
        "devices_connected": connected,
        "probes_sent": probes,
        "probes_failed": probes_failed,
        "commands_parsed": counts.get("parsed", 0),
        "commands_empty": counts.get("empty", 0),
        "commands_unparsed": counts.get("unparsed", 0),
        "commands_raw": counts.get("raw", 0),
        "commands_failed": counts.get("failed", 0),
        "redacted_lines": redacted,
    }
