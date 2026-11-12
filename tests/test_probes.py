"""Reachability probes: the single exception to the show-only rule.

A probe must be impossible to turn into anything other than `ping <literal
address>`, must stay off unless explicitly enabled, and must never leak into
the show-command allowlist.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from netstate.collector import (
    DEFAULT_COMMANDS_FILE,
    CollectionError,
    CommandNotAllowed,
    CommandPolicy,
    CommandResult,
    _probe_device,
    neighbour_addresses,
    summarise_devices,
)


def policy(**os_specs) -> CommandPolicy:
    return CommandPolicy(os_specs, source="<test>")


class ProbeAllowlistTestCase(unittest.TestCase):
    def test_the_shipped_allowlist_offers_probes_for_both_platforms(self):
        shipped = CommandPolicy.load(DEFAULT_COMMANDS_FILE)
        self.assertTrue(shipped.probes_enabled_for("iosxe"))
        self.assertTrue(shipped.probes_enabled_for("iosxr"))

    def test_probes_are_not_part_of_the_show_command_allowlist(self):
        # Nothing in `commands` may be a ping: the two lists never mix.
        shipped = CommandPolicy.load(DEFAULT_COMMANDS_FILE)
        for os_name in shipped.os_names:
            for command in shipped.allowed_commands(os_name):
                self.assertTrue(command.startswith("show "), command)
            with self.assertRaises(CommandNotAllowed):
                shipped.assert_allowed(os_name, "ping 10.0.0.1")

    def test_a_ping_placed_in_the_parse_list_is_refused(self):
        with self.assertRaises(CommandNotAllowed):
            policy(iosxe={"parse": ["show version", "ping 10.0.0.1"]})

    def test_only_the_one_probe_template_is_accepted(self):
        for bad in ("ping {addr} repeat 1000", "ping 198.51.100.8", "traceroute {addr}",
                    "ping {addr} source {source}", "telnet {addr}"):
            with self.assertRaises(CommandNotAllowed, msg=bad):
                policy(iosxe={"parse": ["show version"], "probe": [bad]})

    def test_probe_must_be_a_list(self):
        with self.assertRaises(CollectionError):
            policy(iosxe={"parse": ["show version"], "probe": "ping {addr}"})

    def test_an_os_without_a_probe_list_refuses_to_render_one(self):
        no_probes = policy(iosxe={"parse": ["show version"]})
        self.assertFalse(no_probes.probes_enabled_for("iosxe"))
        with self.assertRaises(CommandNotAllowed):
            no_probes.render_probe("iosxe", "10.0.0.1")


class ProbeRenderingTestCase(unittest.TestCase):
    def setUp(self):
        self.policy = policy(iosxe={"parse": ["show version"], "probe": ["ping {addr}"]})

    def test_a_valid_address_renders_exactly_one_ping(self):
        self.assertEqual(self.policy.render_probe("iosxe", "10.0.12.2"), "ping 10.0.12.2")
        self.assertEqual(
            self.policy.render_probe("iosxe", "2001:db8:12::1"), "ping 2001:db8:12::1"
        )

    def test_addresses_are_normalised_before_they_are_sent(self):
        self.assertEqual(
            self.policy.render_probe("iosxe", " 2001:0db8:0012:0000::0001 "),
            "ping 2001:db8:12::1",
        )

    def test_anything_that_is_not_an_ip_address_is_refused(self):
        for bad in (
            "10.0.12.2 ; reload",
            "10.0.12.2 | include x",
            "router1.example.net",
            "10.0.12.2 repeat 10000",
            "10.0.12.300",
            "",
            "   ",
            "-1",
            "10.0.12.0/30",
        ):
            with self.assertRaises(CommandNotAllowed, msg=bad):
                self.policy.render_probe("iosxe", bad)

    def test_an_unknown_os_is_refused(self):
        with self.assertRaises(CollectionError):
            self.policy.render_probe("nxos", "10.0.12.2")


class ProbeTargetTestCase(unittest.TestCase):
    """Targets come only from what the device itself has learned."""

    def arp(self, entries):
        interfaces: dict = {}
        for interface, address, origin in entries:
            interfaces.setdefault(interface, {"ipv4": {"neighbors": {}}})
            interfaces[interface]["ipv4"]["neighbors"][address] = {
                "ip": address, "link_layer_address": "aabb.cc00.0100",
                "origin": origin, "age": "4", "type": "ARPA", "protocol": "Internet",
            }
        return {"interfaces": interfaces}

    def test_dynamic_arp_entries_become_targets(self):
        parsed = self.arp([("GigabitEthernet2", "10.0.12.2", "dynamic")])
        self.assertEqual(neighbour_addresses(parsed), ["10.0.12.2"])

    def test_static_entries_are_not_probed(self):
        # A static entry is the device's own address.
        parsed = self.arp([("GigabitEthernet2", "10.0.12.1", "static")])
        self.assertEqual(neighbour_addresses(parsed), [])

    def test_targets_are_sorted_so_a_run_probes_the_same_order(self):
        parsed = self.arp([
            ("GigabitEthernet2", "10.0.12.10", "dynamic"),
            ("GigabitEthernet2", "10.0.12.2", "dynamic"),
            ("GigabitEthernet3", "198.51.100.13", "dynamic"),
        ])
        self.assertEqual(
            neighbour_addresses(parsed), ["10.0.12.2", "10.0.12.10", "198.51.100.13"]
        )

    def test_ipv6_neighbour_tables_are_understood_in_both_spellings(self):
        for key in ("interface", "interfaces"):
            parsed = {key: {"GigabitEthernet2": {
                "interface": "GigabitEthernet2",
                "neighbors": {"2001:db8:12::1": {
                    "ip": "2001:db8:12::1", "link_layer_address": "aabb.cc00.0100",
                    "age": "1", "neighbor_state": "REACH"}}}}}
            self.assertEqual(neighbour_addresses(parsed), ["2001:db8:12::1"], key)

    def test_junk_is_not_turned_into_a_target(self):
        parsed = {"interfaces": {"GigabitEthernet2": {"ipv4": {"neighbors": {
            "Incomplete": {"ip": "Incomplete", "link_layer_address": "-",
                           "origin": "dynamic", "age": "-", "type": "ARPA",
                           "protocol": "Internet"}}}}}}
        self.assertEqual(neighbour_addresses(parsed), [])

    def test_empty_and_malformed_input(self):
        self.assertEqual(neighbour_addresses(None), [])
        self.assertEqual(neighbour_addresses({}), [])
        self.assertEqual(neighbour_addresses({"interfaces": "nonsense"}), [])

    def test_link_local_multicast_loopback_and_unspecified_are_not_targets(self):
        """BUG-110: such a neighbour cannot be pinged by address alone.

        IOS-XE stops at 'Output Interface:' for an FE80:: target and the probe
        times out, recorded as a failure against a neighbour that is there.
        """
        parsed = self.arp([
            ("GigabitEthernet2", "10.0.12.2", "dynamic"),
            ("GigabitEthernet2", "169.254.1.1", "dynamic"),
            ("GigabitEthernet2", "224.0.0.5", "dynamic"),
            ("GigabitEthernet2", "127.0.0.1", "dynamic"),
            ("GigabitEthernet2", "0.0.0.0", "dynamic"),
        ])
        parsed["interface"] = {"GigabitEthernet2": {"interface": "GigabitEthernet2", "neighbors": {
            address: {"ip": address, "link_layer_address": "aabb.cc00.0100", "neighbor_state": "REACH"}
            for address in ("FE80::A8BB:CCFF:FE00:100", "2001:db8:12::1", "FF02::1", "::1", "::")
        }}}
        self.assertEqual(neighbour_addresses(parsed), ["10.0.12.2", "2001:db8:12::1"])


class AFailedProbeIsNotAFailedCommand(unittest.TestCase):
    """BUG-110: a ping that could not complete is a finding, so the run is not partial for it."""

    def test_probes_are_counted_apart_from_the_show_commands(self):
        entry = lambda command, status: {"command": command, "status": status, "redacted_lines": 0}
        summary = summarise_devices({"R1": {"connected": True, "commands": [
            entry("show version", "parsed"),
            entry("ping 10.0.12.2", "parsed"),
            entry("ping 10.0.12.3", "failed"),
        ]}})
        self.assertEqual(
            (summary["commands_parsed"], summary["commands_failed"], summary["probes_sent"], summary["probes_failed"]),
            (1, 0, 2, 1),
        )


class ProbeDevice:
    """Answers every ping and records what it was sent."""

    def __init__(self):
        self.executed: list[str] = []

    def execute(self, command, timeout=None):
        self.executed.append(command)
        return "Success rate is 100 percent (5/5)"

    def parse(self, command, output=None):
        return {"ping": {"statistics": {"success_rate_percent": 100.0}}}


class ProbesStayInTheDefaultVrf(unittest.TestCase):
    """BUG-111: `ping <address>` runs in the default VRF, so only its neighbours are targets.

    NX-OS reads ARP and ND with `vrf all`, and a bare ping to a mgmt0 or a
    VRF-lite neighbour went out of the default table and came back
    'unreachable' for a neighbour that is there.
    """

    ARP = {"interfaces": {
        interface: {"ipv4": {"neighbors": {address: {
            "ip": address, "link_layer_address": "5254.0012.0001", "origin": "dynamic",
            "age": "00:01:02", "physical_interface": interface,
        }}}}
        for interface, address in (
            ("Ethernet1/1", "10.0.12.1"), ("Vlan100", "198.51.100.2"), ("mgmt0", "192.0.2.15"),
        )
    }}
    ND = {"interfaces": {
        interface: {"interface": interface, "neighbors": {address: {
            "ip": address, "link_layer_address": "5254.0012.0003", "origin": "dynamic",
        }}}
        for interface, address in (("Ethernet1/1", "2001:db8:12::3"), ("Vlan100", "2001:db8:100::2"))
    }}
    INTERFACES = {
        "Ethernet1/1": {"vrf": "default", "interface_status": "protocol-up/link-up/admin-up"},
        "Vlan100": {"vrf": "CUST", "interface_status": "protocol-up/link-up/admin-up"},
        "mgmt0": {"vrf": "management", "interface_status": "protocol-up/link-up/admin-up"},
    }

    def probe(self, states):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        collected = []
        for command, parsed in states.items():
            path = root / "LEAF1" / "state" / f"{command.replace(' ', '_')}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(parsed), encoding="utf-8")
            collected.append(CommandResult(command=command, status="parsed",
                                           state_file=str(path.relative_to(root))))
        device = ProbeDevice()
        nxos = policy(nxos={"parse": list(states), "probe": ["ping {addr}"]})
        _probe_device(device, "nxos", nxos, root, "LEAF1", collected, 100, 10)
        return device.executed

    def test_only_neighbours_on_default_vrf_interfaces_are_pinged(self):
        sent = self.probe({
            "show ip arp detail vrf all": self.ARP,
            "show ipv6 neighbor detail vrf all": self.ND,
            "show ip interface vrf all": self.INTERFACES,
            "show ipv6 interface vrf all": {"Ethernet1/1": self.INTERFACES["Ethernet1/1"]},
        })
        self.assertEqual(sent, ["ping 10.0.12.1", "ping 2001:db8:12::3"])

    def test_without_the_interface_tables_no_vrf_all_neighbour_is_pinged(self):
        # The VRF of each neighbour is then unknown: not probed, never guessed.
        sent = self.probe({
            "show ip arp detail vrf all": self.ARP,
            "show ipv6 neighbor detail vrf all": self.ND,
        })
        self.assertEqual(sent, [])

    def test_a_default_vrf_table_needs_no_interface_table(self):
        # IOS-XE `show ip arp` lists the global table only.
        sent = self.probe({"show ip arp": {"interfaces": {"GigabitEthernet2": self.ARP["interfaces"]["Ethernet1/1"]}}})
        self.assertEqual(sent, ["ping 10.0.12.1"])

    def test_the_interface_filter_reads_either_spelling_of_a_name(self):
        self.assertEqual(neighbour_addresses(self.ARP, interfaces={"Eth1/1"}), ["10.0.12.1"])


class TwoProbesNeverShareAFile(unittest.TestCase):
    """BUG-248: `ping 2001:db8::1` and `ping 2001:db8:1::` slug alike, and the second overwrote the first."""

    def test_each_target_keeps_its_own_raw_and_state_file(self):
        nd = {"interfaces": {"GigabitEthernet2": {"interface": "GigabitEthernet2", "neighbors": {
            address: {"ip": address, "link_layer_address": "5254.0012.0003", "origin": "dynamic"}
            for address in ("2001:db8::1", "2001:db8:1::")
        }}}}
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        path = root / "R1" / "state" / "show_ipv6_neighbors.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(nd), encoding="utf-8")
        collected = [CommandResult(command="show ipv6 neighbors", status="parsed",
                                   state_file=str(path.relative_to(root)))]

        class Answers(ProbeDevice):
            def execute(self, command, timeout=None):
                super().execute(command, timeout)
                return f"{command}: Success rate is 100 percent (5/5)"

        results = _probe_device(
            Answers(), "iosxe", policy(iosxe={"parse": ["show ipv6 neighbors"], "probe": ["ping {addr}"]}),
            root, "R1", collected, 100, 10,
        )
        self.assertEqual([r.command for r in results], ["ping 2001:db8::1", "ping 2001:db8:1::"])
        self.assertEqual(len({r.raw_file for r in results}), 2)
        self.assertEqual(len({r.state_file for r in results}), 2)
        for result in results:
            self.assertTrue((root / result.raw_file).read_text().startswith(result.command + ":"))


class AnAsaArpTableIsReadForTargets(unittest.TestCase):
    """BUG-258: ASA keys its ARP table by nameif at the top level, with no `interfaces` above it.

    The probe reader looked only under `interfaces`, so an ASA collected with
    --verify-reachability was marked probed and never pinged anything. The
    topology already read the layout; both now read it the same way.
    """

    # Keyed by nameif, as the ASA parser writes it.
    ARP = {
        "inside": {"ipv4": {"neighbors": {"10.0.12.1": {"ip": "10.0.12.1", "link_layer_address": "aabb.cc00.0100", "age": "12"}}}},
        "outside": {"ipv4": {"neighbors": {"192.0.2.1": {"ip": "192.0.2.1", "link_layer_address": "aabb.cc00.0200", "age": "3"}}}},
    }

    def test_the_neighbours_under_each_nameif_are_targets(self):
        self.assertEqual(neighbour_addresses(self.ARP), ["10.0.12.1", "192.0.2.1"])

    def test_an_asa_is_pinged_from_its_show_arp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        path = root / "fw-1" / "state" / "show_arp.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(self.ARP), encoding="utf-8")
        collected = [CommandResult(command="show arp", status="parsed", state_file=str(path.relative_to(root)))]
        device = ProbeDevice()
        _probe_device(
            device, "asa", policy(asa={"parse": ["show arp"], "probe": ["ping {addr}"]}), root, "fw-1", collected, 20, 10,
        )
        self.assertEqual(device.executed, ["ping 10.0.12.1", "ping 192.0.2.1"])

    def test_a_table_that_is_not_that_layout_is_still_no_target(self):
        self.assertEqual(neighbour_addresses({"inside": {"ipv4": "nonsense"}}), [])
        self.assertEqual(neighbour_addresses({"inside": {"ipv4": {}}, "version": "9.16"}), [])


class AProbeIsFoundWhateverCaseTheAddressIsPrintedIn(unittest.TestCase):
    """BUG-247: IOS-XE prints IPv6 upper-case and the ping is sent lower-case, so an IPv6-only link read 'not probed'."""


    def test_probe_results_are_keyed_by_one_spelling_of_the_address(self):
        from netstate.collector import Snapshot

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        state = root / "R1" / "state" / "ping.json"
        state.parent.mkdir(parents=True)
        state.write_text(json.dumps({"ping": {"statistics": {"success_rate_percent": 100.0}}}))
        (root / "manifest.json").write_text(json.dumps({"snapshot_id": "run-1", "devices": {"R1": {
            "os": "iosxe", "connected": True, "commands": [
                {"command": "ping 2001:DB8:12:0::2", "status": "parsed", "state_file": "R1/state/ping.json"},
            ]}}}))
        probes = Snapshot.load(root, db=root / "none.db").probe_results()
        self.assertEqual(list(probes["R1"]), ["2001:db8:12::2"])


class ShippedAllowlistTestCase(unittest.TestCase):
    def test_every_new_command_is_a_show_command(self):
        raw = yaml.safe_load(DEFAULT_COMMANDS_FILE.read_text(encoding="utf-8"))
        for os_name, spec in raw.items():
            for key in ("parse", "raw_only"):
                for command in spec.get(key) or []:
                    self.assertTrue(command.startswith("show "), f"{os_name}.{key}: {command}")

    def test_addressing_and_neighbour_table_commands_are_collected(self):
        shipped = CommandPolicy.load(DEFAULT_COMMANDS_FILE)
        for command in ("show ip interface", "show ipv6 interface", "show ip arp",
                        "show ipv6 neighbors"):
            self.assertIn(command, shipped.allowed_commands("iosxe"), command)
        for command in ("show ipv4 vrf all interface", "show ipv6 interface",
                        "show arp detail", "show ipv6 neighbors"):
            self.assertIn(command, shipped.allowed_commands("iosxr"), command)


if __name__ == "__main__":
    unittest.main()
