"""What the first NX-OS field run (13 November 2026) found the collector saying wrongly.

1. DiscoNet reads three NX-OS commands from their text, as it reads
   `show spanning-tree`: Genie's schema fails `show ipv6 neighbor detail vrf
   all` on 9.3 and 10.x, has no NX-OS parser for `show spanning-tree mst
   configuration`, and fails `show ntp peer-status` when no peer is
   configured. An `unparsed` status on any of them is no collection gap.
2. A command the platform reads from text that printed output, but whose
   parser returned nothing, is not `empty`: NX-OS `show interface trunk`
   printed 2 to 20 KB on every switch and was recorded `empty`, a statement
   that the switch had nothing to report. It is `unparsed`, with the text kept.
3. NX-OS creates `egress-loadbalance-resolution-` for itself on the Nexus
   9000. It is the platform's own VRF, not a service anybody configured.

Every output here is written by hand; no device's output is in this file.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from netstate import collector
from netstate.collector import CommandPolicy, Snapshot, _collect_command
from netstate.naming import is_platform_own_vrf
from netstate.platforms import platform_for
from tests.test_collector_collection import FakeDevice, SchemaEmptyParserError

NXOS_POLICY = CommandPolicy(
    {"nxos": {"parse": ["show interface trunk", "show version", "show ip ospf neighbors vrf all"]}}
)

# The shape `show interface trunk` prints on NX-OS, abridged, with made-up ports.
TRUNK_TEXT = """
--------------------------------------------------------------------------------
Port          Native  Status        Port
              Vlan                  Channel
--------------------------------------------------------------------------------
Eth1/1        1       trunking      Po10
Eth1/2        1       trunking      Po10
Po10          1       trunking      --

--------------------------------------------------------------------------------
Port          Vlans Allowed on Trunk
--------------------------------------------------------------------------------
Eth1/1        1-4094
Eth1/2        1-4094
Po10          1-4094
"""


def _nxos_device(raw, parsed):
    device = FakeDevice(raw=raw, parsed=parsed)
    device.name = "c-sw-1"
    device.os = "nxos"
    return device


class TheThreeCommandsReadFromTextAreNoGap(unittest.TestCase):
    COMMANDS = (
        "show ipv6 neighbor detail vrf all",
        "show spanning-tree mst configuration",
        "show ntp peer-status",
    )

    def snapshot(self, os_name, commands):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        devices = {
            "SW1": {
                "name": "SW1",
                "os": os_name,
                "connected": True,
                "error": None,
                "commands": [
                    {"command": command, "status": status, "state_file": None, "raw_file": None,
                     "redacted_lines": 0, "seconds": 1.0, "detail": detail}
                    for command, status, detail in commands
                ],
            }
        }
        (root / "manifest.json").write_text(json.dumps({
            "disconet_version": "0.1.0", "snapshot_id": "20261116T090000Z",
            "created_at": "2026-11-16T09:00:00+00:00", "devices": devices,
        }), encoding="utf-8")
        return Snapshot.load(root)

    def test_nxos_lists_none_of_them_unparsed(self):
        commands = [("show version", "parsed", None)] + [
            (command, "unparsed", "SchemaMissingKeyError") for command in self.COMMANDS
        ]
        self.assertEqual(self.snapshot("nxos", commands).gaps(), [])

    def test_the_registry_names_all_three(self):
        names = {CommandPolicy.normalise(c) for c in platform_for("nxos").text_parsed}
        for command in self.COMMANDS:
            with self.subTest(command=command):
                self.assertIn(CommandPolicy.normalise(command), names)

    def test_on_iosxe_an_unparsed_mst_configuration_is_still_a_gap(self):
        gaps = self.snapshot("iosxe", [
            ("show version", "parsed", None),
            ("show spanning-tree mst configuration", "unparsed", "ParserNotFound"),
        ]).gaps()
        self.assertEqual(len(gaps), 1, gaps)
        self.assertIn("show spanning-tree mst configuration unparsed", gaps[0])


class OutputThatParsedToNothingIsNotEmpty(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._pause = collector.RETRY_PAUSE
        collector.RETRY_PAUSE = 0

    def tearDown(self):
        collector.RETRY_PAUSE = self._pause
        self._tmp.cleanup()

    def collect(self, device, command):
        return _collect_command(device, "nxos", command, NXOS_POLICY, self.root, "c-sw-1", True, 120)

    def test_a_text_read_command_with_output_and_no_parse_is_unparsed_and_kept(self):
        result = self.collect(_nxos_device({"show interface trunk": TRUNK_TEXT},
                                           {"show interface trunk": {}}), "show interface trunk")
        self.assertEqual(result.status, "unparsed")
        self.assertIn("returned no data", result.detail)
        self.assertIn("line(s) of output", result.detail)
        self.assertIsNone(result.state_file)
        self.assertIn("Eth1/1", (self.root / result.raw_file).read_text(encoding="utf-8"))

    def test_the_same_command_with_nothing_printed_is_still_empty(self):
        result = self.collect(_nxos_device({"show interface trunk": "\n  \n"},
                                           {"show interface trunk": {}}), "show interface trunk")
        self.assertEqual(result.status, "empty")

    def test_the_parser_saying_empty_is_still_believed(self):
        result = self.collect(
            _nxos_device({"show ip ospf neighbors vrf all": "header only\n"},
                         {"show ip ospf neighbors vrf all": SchemaEmptyParserError("empty")}),
            "show ip ospf neighbors vrf all",
        )
        self.assertEqual(result.status, "empty")

    def test_a_command_not_read_from_text_keeps_today_s_status(self):
        # Without a text reader nothing proves the output held data; the
        # detail says how much there was, the status is unchanged.
        result = self.collect(
            _nxos_device({"show ip ospf neighbors vrf all": "line one\nline two\n"},
                         {"show ip ospf neighbors vrf all": {}}),
            "show ip ospf neighbors vrf all",
        )
        self.assertEqual(result.status, "empty")
        self.assertIn("2 line(s) of output", result.detail)

    def test_an_unparsed_trunk_table_is_no_gap(self):
        # It is in NX-OS's text_parsed already; the new status must not make
        # the document report it missing.
        self.assertIn("show interface trunk", platform_for("nxos").text_parsed)


class NxosVrfOfItsOwn(unittest.TestCase):
    def test_the_load_balance_resolution_vrf_is_the_platform_s(self):
        self.assertTrue(is_platform_own_vrf("egress-loadbalance-resolution-", "nxos"))

    def test_read_on_its_own_os_only(self):
        self.assertFalse(is_platform_own_vrf("egress-loadbalance-resolution-", "iosxe"))

    def test_an_operator_vrf_is_theirs(self):
        for name in ("CUSTOMER-A", "egress", "egress-loadbalance-resolution-x", "management", None, ""):
            with self.subTest(name=name):
                self.assertFalse(is_platform_own_vrf(name, "nxos"))


class _Stub:
    """Just what the hostname reader asks of a snapshot: a configuration and a `show version` parse."""

    def __init__(self, config: str, version: dict | None):
        self._config, self._version = config, version

    def config(self, device):
        return self._config

    def state(self, device, command):
        return self._version if command == "show version" else None


def _nxos_version(name: str) -> dict:
    # The shape Genie's NX-OS `show version` parser returns, abridged.
    return {"platform": {"hardware": {"device_name": name, "model": "Nexus7700 C7706"},
                         "software": {"system_version": "8.4(7)"}}}


class AVdcIsNamedAsShowVersionNamesIt(unittest.TestCase):
    """NX-OS field run, 20 November 2026: a Nexus 7000 VDC was named by half its name.

    A non-default VDC runs under `<default VDC switchname>-<VDC name>`: its
    prompt, `show version`'s `Device name:` and its CDP advertisement all say
    so. Its `hostname` line, where one was set, carries the VDC part only.
    One member of a vPC pair was documented by the VDC part, its peer (with
    no `hostname` line) by the whole name, and the peer's CDP neighbour
    matched no node. Made-up names throughout.
    """

    def name(self, config, version, os_name="nxos"):
        from netstate.readers import _hostname_from

        return _hostname_from(_Stub(config, version), "dev", os_name)

    def test_the_whole_name_from_show_version_wins_over_the_vdc_part(self):
        self.assertEqual(self.name("hostname CORE\n", _nxos_version("c-n7k-1-CORE")), "c-n7k-1-CORE")

    def test_without_a_hostname_line_show_version_names_it_as_before(self):
        self.assertEqual(self.name("feature lacp\n", _nxos_version("c-n7k-2-CORE")), "c-n7k-2-CORE")

    def test_a_nexus_without_vdcs_reads_the_same_name_either_way(self):
        self.assertEqual(self.name("hostname c-sw-1\n", _nxos_version("c-sw-1")), "c-sw-1")

    def test_with_no_show_version_parse_the_configuration_still_names_it(self):
        self.assertEqual(self.name("hostname CORE\n", None), "CORE")

    def test_ios_xe_keeps_the_configuration_first(self):
        version = {"version": {"hostname": "from-version"}}
        self.assertEqual(self.name("hostname from-config\n", version, "iosxe"), "from-config")

    def test_only_nx_os_reads_show_version_first(self):
        flagged = sorted(name for name in ("nxos", "iosxe", "iosxr", "junos", "asa")
                         if platform_for(name) is not None and platform_for(name).hostname_from_version)
        self.assertEqual(flagged, ["nxos"])


if __name__ == "__main__":
    unittest.main()
