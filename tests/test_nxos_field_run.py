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


if __name__ == "__main__":
    unittest.main()
