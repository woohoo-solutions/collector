"""The platform registry is the only place an operating system is described.

Every test here states the rule that lets a third OS be one entry in
`platforms.py` and one block in `commands.yaml`, rather than a branch in every
module that reads a device.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest import mock

import yaml

from netstate import collector, naming, platforms
from netstate.platforms import (
    DEFAULT_OS,
    PLATFORMS,
    Platform,
    VersionFacts,
    abbreviations_for,
    accent_for,
    detect,
    hint_from_banner,
    label_for,
    platform_for,
    platform_keys,
)

PACKAGE = Path(platforms.__file__).parent
# The rule holds for the engine and the document generator alike: every
# module of both packages but the registry itself.


class RegistryAgreesWithTheAllowlist(unittest.TestCase):
    def setUp(self):
        self.allowlist = yaml.safe_load((PACKAGE / "commands.yaml").read_text())

    def test_every_platform_has_an_allowlist_and_every_allowlist_a_platform(self):
        self.assertEqual(set(platform_keys()), set(self.allowlist))

    def test_a_platform_only_names_commands_its_allowlist_sends_unconditionally(self):
        # The address inventory and ARP readers run on every collection, so the
        # commands they read must be in `parse`, not behind a feature.
        for platform in PLATFORMS:
            sent = {collector.CommandPolicy.normalise(c) for c in self.allowlist[platform.key]["parse"]}
            named = {platform.arp_command} | {
                command for commands in platform.address_commands.values() for command in commands
            }
            for command in named:
                with self.subTest(platform=platform.key, command=command):
                    self.assertIn(collector.CommandPolicy.normalise(command), sent)

    def test_ios_xr_reads_every_vrf_s_ipv6_first(self):
        """BUG-113: IOS-XR IPv6 addressing was asked of the default VRF only."""
        self.assertIn("show ipv6 vrf all interface", self.allowlist["iosxr"]["parse"])
        self.assertEqual(
            platform_for("iosxr").address_commands["ipv6"][0], "show ipv6 vrf all interface"
        )

    def test_the_default_os_is_a_registered_platform(self):
        self.assertIn(DEFAULT_OS, platform_keys())

    def test_short_names_and_keys_are_unique(self):
        self.assertEqual(len({p.key for p in PLATFORMS}), len(PLATFORMS))
        self.assertEqual(len({p.short for p in PLATFORMS}), len(PLATFORMS))


class Detection(unittest.TestCase):
    def test_a_prompt_only_one_os_prints_names_it(self):
        self.assertEqual(detect("RP/0/RP0/CPU0:XR1#"), "iosxr")
        self.assertEqual(detect("sysadmin-vm:0_RP0# "), "iosxr")

    def test_a_version_banner_names_it(self):
        self.assertEqual(detect("Cisco IOS XE Software, Version 17.09.04a"), "iosxe")
        self.assertEqual(detect("Cisco IOS XR Software, Version 7.9.2"), "iosxr")

    def test_a_banner_naming_only_cisco_ios_is_classic_ios_and_one_naming_xe_anywhere_is_xe(self):
        self.assertEqual(detect("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(7)E"), "ios")
        # IOS-XE 17 prints both lines; the XE line decides.
        self.assertEqual(
            detect("Cisco IOS XE Software, Version 17.03.04a\nCisco IOS Software [Amsterdam], ASR1000 Software"),
            "iosxe",
        )
        # The 3.x releases spelled it with a hyphen.
        self.assertEqual(detect("Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software"), "iosxe")
        self.assertEqual(detect("Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a"), "iosxe")
        self.assertEqual(detect("Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 18.4R3"), "junos")

    def test_classic_ios_reads_like_iosxe_under_its_own_key(self):
        from netstate.platforms import IOS, IOSXE
        self.assertEqual(IOS.key, "ios")
        self.assertEqual(IOS.abbreviations, IOSXE.abbreviations)
        self.assertEqual(IOS.session_setup, IOSXE.session_setup)
        self.assertEqual(IOS.arp_command, IOSXE.arp_command)
        self.assertEqual(PLATFORMS[-1], IOS)

    def test_a_plain_cisco_prompt_proves_nothing(self):
        self.assertEqual(detect("R1>\nR1>enable\nPassword:\nR1#\n"), "")
        self.assertEqual(detect(""), "")

    def test_the_collector_asks_the_registry(self):
        self.assertEqual(collector.detect_os("RP/0/RSP0/CPU0:asr9k-pe1#"), "iosxr")


class Lookups(unittest.TestCase):
    def test_an_unregistered_os_is_none_not_an_error(self):
        self.assertIsNone(platform_for("linux"))
        self.assertIsNone(platform_for(None))
        self.assertIsNone(platform_for(""))

    def test_lookups_are_case_insensitive_like_the_testbed_field(self):
        self.assertIs(platform_for("IOSXR"), platform_for("iosxr"))

    def test_labels_and_accents_fall_back_rather_than_fail(self):
        self.assertEqual(label_for("iosxe"), "IOS-XE")
        self.assertEqual(label_for("linux", "LINUX"), "LINUX")
        self.assertIsNone(label_for("linux"))
        self.assertEqual(accent_for("iosxr"), "xr")
        self.assertEqual(accent_for("linux"), "unknown")

    def test_an_unknown_os_abbreviates_interfaces_as_the_default_os_does(self):
        self.assertIs(abbreviations_for(None), abbreviations_for(DEFAULT_OS))
        self.assertIs(abbreviations_for("linux"), abbreviations_for(DEFAULT_OS))

    def test_version_facts_survive_a_missing_or_malformed_parse(self):
        for platform in PLATFORMS:
            self.assertEqual(platform.version(None), VersionFacts())
            self.assertEqual(platform.version({}), VersionFacts())
        self.assertEqual(platform_for("iosxe").version({"version": "not a dict"}), VersionFacts())

    def test_each_platform_reads_show_version_where_its_parser_puts_it(self):
        xe = platform_for("iosxe").version(
            {"version": {"version": "17.9.4a", "platform": "ASR-920", "hostname": "pe1"}}
        )
        self.assertEqual(xe, VersionFacts("17.9.4a", "ASR-920", "pe1"))
        xr = platform_for("iosxr").version(
            {"software_version": "7.9.2", "device_family": "NCS540", "hostname": "pe2"}
        )
        self.assertEqual(xr, VersionFacts("7.9.2", "NCS540", "pe2"))

    def test_iosxe_reads_show_version_text_where_the_parser_failed(self):
        """BUG-224: the platform and the switch role read an unparsed `show version` from its text."""
        xe = platform_for("iosxe")
        self.assertEqual(
            xe.version_from_text(
                "Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software "
                "(cat4500e-UNIVERSALK9-M), Version 03.06.06E RELEASE SOFTWARE (fc1)\n"
                "sw-1 uptime is 1 week, 2 days\n"
            ),
            VersionFacts("03.06.06E", "Catalyst 4500 L3 Switch", "sw-1"),
        )
        # No banner the reader knows: the chassis line names the platform, as
        # it does in the parse.
        self.assertEqual(
            xe.version_from_text("cisco C9300-48P (X86) processor with 1419044K/6147K bytes of memory.\n").platform,
            "C9300-48P",
        )
        for platform in PLATFORMS:
            self.assertEqual(platform.version_from_text(None), VersionFacts())

    def test_the_session_setup_is_a_constant_and_alters_nothing(self):
        # Two spellings of "do not paginate", and nothing else: Cisco's
        # `terminal ...` and Junos's `set cli ...`, which is an operational
        # mode setting for this session despite the verb. Anything else here
        # is a change to the read-only guarantee, and this test is where it
        # is noticed.
        for platform in PLATFORMS:
            for command in platform.session_setup:
                self.assertIsInstance(command, str)
                self.assertTrue(
                    command.startswith(("terminal ", "set cli ")),
                    f"{platform.key}: {command!r} is not a terminal setting",
                )
                self.assertNotIn(
                    command.split()[0], {"configure", "config", "edit", "commit", "load"},
                )


# --------------------------------------------------------------------------
# The rule the whole module exists for
# --------------------------------------------------------------------------

FAKE = Platform(
    key="fakeos",
    label="Fake-OS",
    vendor="Acme",
    examples="a fixture",
    short="fk",
    colour_light="#123456",
    colour_dark="#abcdef",
    abbreviations={"zz": "ZettaEthernet"},
    session_setup=("set cli screen-length 0",),
    has_enable=False,
    prompts=(re.compile(r"\[acme:\S+\]>"),),
    version_markers=("acme fake os",),
    ssh_banner_hints=("acme-ssh",),
    address_commands={"ipv4": ("show ip interface",), "ipv6": (), "brief_ipv4": (), "brief_ipv6": ()},
    arp_command="show ip arp",
    version_facts=lambda parsed: VersionFacts(
        software=str(parsed.get("sw", "")), platform=str(parsed.get("hw", "")),
        hostname=str(parsed.get("name", "")),
    ),
)


def registered(*extra: Platform):
    """The registry with more platforms in it, for the duration of a test."""
    everything = PLATFORMS + extra
    return mock.patch.multiple(
        platforms,
        PLATFORMS=everything,
        _BY_KEY={p.key: p for p in everything},
    )


class AThirdOsIsOneEntry(unittest.TestCase):
    """Nothing outside platforms.py has to change for a new OS to be read."""

    def test_the_registry_answers_for_it_everywhere_at_once(self):
        with registered(FAKE):
            self.assertIs(platform_for("fakeos"), FAKE)
            self.assertEqual(label_for("fakeos"), "Fake-OS")
            self.assertEqual(accent_for("fakeos"), "fk")
            self.assertEqual(detect("[acme:sw1]> "), "fakeos")
            self.assertEqual(detect("Acme Fake OS release 9"), "fakeos")
            self.assertEqual(hint_from_banner("SSH-2.0-acme-ssh_1.0"), "fakeos")
            self.assertEqual(
                FAKE.version({"sw": "9.1", "hw": "Box-1", "name": "sw1"}),
                VersionFacts("9.1", "Box-1", "sw1"),
            )

    def test_its_interface_abbreviations_expand_without_touching_naming(self):
        with registered(FAKE):
            self.assertEqual(naming.normalise_interface("zz0/1", "fakeos"), "ZettaEthernet0/1")
        # And are gone again with it: the registry is the only source.
        self.assertEqual(naming.normalise_interface("zz0/1", "fakeos"), "zz0/1")


    def test_the_collector_sends_its_own_session_setup(self):
        # The setup is per platform, read at connect time, and still a
        # constant nothing in a testbed can alter.
        with registered(FAKE):
            self.assertEqual(list(platform_for("fakeos").session_setup), ["set cli screen-length 0"])


class AFixedChassisIsKnownByItsModel(unittest.TestCase):
    """BUG-103: every port of an ASR 920 or an NCS 540 read one slot, a line card that was the whole box."""

    FIXED = {
        "iosxe": ("ASR-920-12CZ-A", "N520-X-4G4Z-A", "C9300-48P", "C9200L-24T-4G", "WS-C3850-24T",
                  "C9500-32C", "ASR1001-X", "ASR1002-X", "ISR4451-X/K9", "C1111-8P"),
        "ios": ("ME-3400E-24TS-M", "ME-3600X-24FS-M", "WS-C2960X-48TS-L"),
        "iosxr": ("N540X-ACC-SYS", "N540-24Z8Q2C-SYS", "NCS-5501-SE", "NCS-55A1-24H"),
        "nxos": ("N9K-C93180YC-FX", "N9K-C9236C", "N3K-C3172PQ-10GE"),
        "junos": ("EX4300-48T", "QFX5120-48Y-8C", "ACX710", "MX204"),
    }
    # Chassis with slots for cards, and a Junos virtual chassis, whose
    # Chassis line names no model.
    MODULAR = {
        "iosxe": ("ASR-903", "NCS4206-SA", "C9407R", "ASR1006-X", ""),
        "ios": ("WS-C6509-E",),
        "iosxr": ("NCS-5508", "ASR-9006-AC-V2", "NCS-55A2-MOD-S"),
        "nxos": ("N9K-C9508", "N7K-C7010"),
        "junos": ("MX960", "EX9208", "PTX10008", "Virtual Chassis"),
    }

    def test_each_os_names_its_fixed_models_and_no_modular_one(self):
        for fixed, table in ((True, self.FIXED), (False, self.MODULAR)):
            for key, pids in table.items():
                for pid in pids:
                    with self.subTest(os=key, pid=pid):
                        self.assertIs(platform_for(key).is_fixed_chassis(pid), fixed)

    def test_a_model_is_read_on_its_own_os(self):
        self.assertFalse(platform_for("nxos").is_fixed_chassis("N540X-ACC-SYS"))


if __name__ == "__main__":
    unittest.main()
