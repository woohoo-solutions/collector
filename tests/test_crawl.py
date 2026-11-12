"""The bounded crawl: the fence, the candidates, the waves and the testbed blocks."""

from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from netstate import collector, crawl
from netstate.collector import (
    CDP_COMMAND, CommandPolicy, DeviceResult, CommandResult, _build_manifest, _crawl, crawled_device,
    slugify,
)
from netstate.crawl import (
    Candidate, CrawlRecord, bridge_capable, cdp_candidates, in_fence, lldp_candidates,
    os_from_description, parse_fence, plan_wave,
)
from tests.helpers import cdp_state, lldp_state


def cdp_entry(name, local, address, capabilities="Switch IGMP", software="Cisco IOS Software, C2960 Software", platform="cisco WS-C2960X-48"):
    return {
        "device_id": name, "local_interface": local, "port_id": "GigabitEthernet1/0/24",
        "platform": platform, "capabilities": capabilities, "software_version": software, "hold_time": 120,
        "entry_addresses": {address: {}} if address else {}, "management_addresses": {address: {}} if address else {},
    }


class FenceAndCapability(unittest.TestCase):
    def test_the_fence_is_read_from_comma_or_space_separated_text_and_judges_an_address(self):
        fence = parse_fence(["10.1.0.0/24, 10.2.0.0/24", "192.0.2.0/25"])
        self.assertEqual([str(n) for n in fence], ["10.1.0.0/24", "10.2.0.0/24", "192.0.2.0/25"])
        self.assertTrue(in_fence("10.2.0.7", fence))
        self.assertFalse(in_fence("198.51.100.7", fence))
        self.assertFalse(in_fence("not an address", fence))
        with self.assertRaises(ValueError):
            parse_fence(["10.1.0.0/33"])

    def test_bridge_capability_is_read_from_cdp_words_and_lldp_keys(self):
        self.assertTrue(bridge_capable("Router Switch IGMP"))
        self.assertTrue(bridge_capable("Switch"))
        self.assertFalse(bridge_capable("Router"))
        self.assertFalse(bridge_capable("Host Phone"))
        self.assertTrue(bridge_capable({"bridge": {"system": True, "enabled": True}}))
        self.assertFalse(bridge_capable({"router": {"system": True}}))
        self.assertFalse(bridge_capable(""))

    def test_the_os_comes_from_the_neighbours_description_through_the_registry(self):
        self.assertEqual(os_from_description("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M)"), "ios")
        self.assertEqual(os_from_description("Cisco IOS XE Software, Version 17.9.4a"), "iosxe")
        self.assertEqual(os_from_description("Juniper Networks, Inc. ex4300-48t Ethernet Switch"), "junos")
        self.assertEqual(os_from_description("Cisco Nexus Operating System (NX-OS) Software 9.3(8)"), "nxos")
        self.assertEqual(os_from_description("Polycom VVX 411"), "")


class Candidates(unittest.TestCase):
    def test_cdp_names_the_switch_its_address_its_capability_and_its_os(self):
        parsed = cdp_state([cdp_entry("SW1.example.net", "GigabitEthernet0/0/1", "10.1.0.11")])
        [candidate] = cdp_candidates("R1", parsed, depth=1)
        self.assertEqual((candidate.name, candidate.address, candidate.os, candidate.via, candidate.via_interface),
                         ("SW1", "10.1.0.11", "ios", "R1", "GigabitEthernet0/0/1"))
        self.assertTrue(bridge_capable(candidate.capabilities))

    def test_lldp_names_the_switch_from_the_system_description_and_the_management_address(self):
        parsed = lldp_state([
            ("GigabitEthernet0/0/2", "ge-0/0/24", {
                "neighbor_id": "SW3", "system_name": "SW3", "port_id": "ge-0/0/24",
                "system_description": "Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 18.4R3",
                "management_address": "10.1.0.13",
                "capabilities": {"bridge": {"system": True, "enabled": True}, "router": {"system": True}},
            }),
        ])
        [candidate] = lldp_candidates("R1", parsed, depth=1)
        self.assertEqual((candidate.name, candidate.address, candidate.os), ("SW3", "10.1.0.13", "junos"))
        self.assertTrue(bridge_capable(candidate.capabilities))

    def test_a_neighbour_with_no_address_is_a_candidate_with_none_so_the_refusal_can_say_so(self):
        [candidate] = cdp_candidates("R1", cdp_state([cdp_entry("SW9", "Gi0/0/3", "")]), depth=1)
        self.assertEqual(candidate.address, "")


class Waves(unittest.TestCase):
    def setUp(self):
        self.fence = parse_fence(["10.1.0.0/24"])

    def wave(self, candidates, known_addresses=(), known_names=(), room=50):
        return plan_wave(candidates, self.fence, set(known_addresses), set(known_names), room)

    def test_every_refusal_names_its_reason(self):
        chosen, refused = self.wave([
            Candidate("SW-OUT", "198.51.100.9", "ios", "R1", capabilities="Switch"),
            Candidate("PHONE", "10.1.0.50", "", "R1", capabilities="Host Phone"),
            Candidate("SW-NOADDR", "", "ios", "R1", capabilities="Switch"),
            Candidate("SW-UNKNOWN", "10.1.0.60", "", "R1", capabilities="Switch"),
            Candidate("SW-OK", "10.1.0.11", "ios", "R1", capabilities="Switch"),
        ])
        self.assertEqual([c.name for c in chosen], ["SW-OK"])
        self.assertEqual(
            {r.name: r.reason for r in refused},
            {
                "SW-OUT": "outside the declared subnets",
                "PHONE": "does not report the Bridge capability",
                "SW-NOADDR": "no management address reported",
                "SW-UNKNOWN": "OS not identifiable from what the neighbour reported",
            },
        )

    def test_a_device_already_known_by_name_or_address_is_neither_visited_nor_a_refusal(self):
        chosen, refused = self.wave(
            [Candidate("R2", "10.1.0.2", "iosxe", "R1", capabilities="Router"),
             Candidate("SW1", "10.1.0.11", "ios", "R1", capabilities="Switch")],
            known_addresses={"10.1.0.11"}, known_names={"r2"},
        )
        self.assertEqual(chosen, [])
        self.assertEqual(refused, [])

    def test_two_switches_with_one_name_are_judged_by_address_and_the_second_refused_with_why(self):
        """BUG-209: candidates were deduplicated by hostname.

        Two factory-default 'Switch' at two addresses: the second was neither
        visited nor recorded as refused. The same name at a new address is
        one device seen twice or two devices; nothing a neighbour reports
        tells which, so it is not visited and the record says why.
        """
        chosen, refused = self.wave([
            Candidate("Switch", "10.1.0.11", "ios", "R1", capabilities="Switch IGMP"),
            Candidate("Switch", "10.1.0.12", "ios", "R1", capabilities="Switch IGMP"),
            Candidate("Switch", "10.1.0.11", "ios", "R2", capabilities="Switch IGMP"),
        ])
        self.assertEqual([(c.name, c.address) for c in chosen], [("Switch", "10.1.0.11")])
        self.assertEqual([(r.name, r.address, r.via) for r in refused], [("Switch", "10.1.0.12", "R1")])
        self.assertIn("name", refused[0].reason)
        self.assertIn("another address", refused[0].reason)

    def test_a_switch_named_like_a_known_device_at_a_new_address_is_refused_with_why(self):
        """BUG-209: a name the testbed or an earlier wave holds, at an address neither does."""
        chosen, refused = self.wave(
            [Candidate("core-1", "10.1.0.13", "ios", "R1", capabilities="Switch"),
             Candidate("R2", "10.1.0.2", "iosxe", "R1", capabilities="Router Switch")],
            known_names={"core-1", "r2"},
        )
        self.assertEqual(chosen, [])
        self.assertEqual([(r.name, r.address) for r in refused], [("core-1", "10.1.0.13"), ("R2", "10.1.0.2")])
        self.assertEqual({r.reason for r in refused}, {refused[0].reason})
        self.assertIn("another address", refused[0].reason)

    def test_a_known_name_a_fence_keeps_out_anyway_is_not_a_refusal(self):
        """A router the testbed lists, named across another link: not a switch, so nothing was declined."""
        chosen, refused = self.wave(
            [Candidate("R2", "10.1.0.2", "iosxe", "R1", capabilities="Router"),
             Candidate("SW1", "198.51.100.11", "ios", "R1", capabilities="Switch"),
             Candidate("SW1", "", "ios", "R2", capabilities="Switch")],
            known_names={"r2", "sw1"},
        )
        self.assertEqual((chosen, refused), ([], []))

    def test_a_switch_two_neighbours_name_is_judged_once_and_the_limit_refuses_the_rest(self):
        chosen, refused = self.wave([
            Candidate("SW1", "10.1.0.11", "ios", "R1", capabilities="Switch"),
            Candidate("SW1", "10.1.0.11", "ios", "R2", capabilities="Switch"),
            Candidate("SW2", "10.1.0.12", "ios", "R1", capabilities="Switch"),
            Candidate("SW3", "10.1.0.13", "ios", "R1", capabilities="Switch"),
        ], room=2)
        self.assertEqual([c.name for c in chosen], ["SW1", "SW2"])
        self.assertEqual([(r.name, r.reason) for r in refused], [("SW3", "crawl limit reached")])

    def test_a_device_two_neighbours_name_is_refused_once_and_not_at_all_when_a_later_report_admits_it(self):
        """BUG-289: a refusal was recorded per report, so the declined count was inflated.

        A switch outside the fence that two routers name, and one no
        neighbour gives an address for, were each declined twice. One a
        later report identifies is visited, and the earlier report that
        could not identify it declined nothing.
        """
        chosen, refused = self.wave([
            Candidate("SW-OUT", "198.51.100.9", "ios", "R1", capabilities="Switch"),
            Candidate("SW-NOADDR", "", "ios", "R1", capabilities="Switch"),
            Candidate("SW-LATE", "10.1.0.60", "", "R1", capabilities="Switch"),
            Candidate("SW-OUT", "198.51.100.9", "ios", "R2", capabilities="Switch"),
            Candidate("sw-noaddr", "", "ios", "R2", capabilities="Switch"),
            Candidate("SW-LATE", "10.1.0.60", "ios", "R2", capabilities="Switch"),
        ])
        self.assertEqual([(c.name, c.via) for c in chosen], [("SW-LATE", "R2")])
        self.assertEqual(
            [(r.name, r.reason, r.via) for r in refused],
            [("SW-OUT", "outside the declared subnets", "R1"),
             ("SW-NOADDR", "no management address reported", "R1")],
        )


class FakeDevice:
    def __init__(self, name, os_name, ip, proxy=None, custom=None, ssh_options=None):
        self.name = name
        self.os = os_name
        self.type = "router"
        cli = {"protocol": "ssh", "ip": ip}
        if proxy is not None:
            cli["proxy"] = proxy
        if ssh_options:
            cli["ssh_options"] = ssh_options
        self.connections = {"cli": cli}
        self.custom = dict(custom or {})
        self.credentials = {}


class FakeTestbed:
    def __init__(self, *devices):
        self.devices = {d.name: d for d in devices}
        self.servers = {}

    def add_device(self, device):
        self.devices[device.name] = device


POLICY = CommandPolicy({
    "iosxe": {"parse": ["show version", CDP_COMMAND, "show lldp neighbors detail"], "raw_only": ["show running-config"]},
    "ios": {"parse": ["show version", CDP_COMMAND, "show lldp neighbors detail"], "raw_only": ["show running-config"]},
})


class CrawlRun(unittest.TestCase):
    """`_crawl` against fakes: waves, the record, the names learned on the way."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # What each device names over CDP, keyed by the name it is collected as.
        self.neighbours: dict[str, list] = {}
        # What each device calls itself, written to its running configuration.
        self.hostnames: dict[str, str] = {}
        self.collected: list[list[str]] = []
        # A device whose turn stops the wave the way Ctrl-C does.
        self.interrupt_at = ""

    def tearDown(self):
        self.tmp.cleanup()

    def collect_wave(self, names, arrived=None):
        """Write the parses a collection would, and answer for every device, each as it finishes."""
        self.collected.append(list(names))
        results = []
        for name in names:
            if name == self.interrupt_at:
                raise KeyboardInterrupt
            result = DeviceResult(name=name, os="ios", connected=True)
            state_dir = self.root / name / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            raw_dir = self.root / name / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            payload = cdp_state(self.neighbours.get(name, []))
            state_file = state_dir / f"{slugify(CDP_COMMAND)}.json"
            state_file.write_text(json.dumps(payload))
            result.commands.append(CommandResult(CDP_COMMAND, "parsed", str(state_file.relative_to(self.root))))
            config = raw_dir / f"{slugify('show running-config')}.txt"
            config.write_text(f"hostname {self.hostnames.get(name, name)}\n")
            result.commands.append(CommandResult("show running-config", "raw", None, str(config.relative_to(self.root))))
            results.append(result)
            if arrived is not None:
                arrived(result)
        return results

    def run_crawl(self, testbed, depth=2, limit=50, fence=("10.1.0.0/24",), refuse=(), testbed_path="testbed.yaml"):
        # Kept on the test too: a crawl the interrupt cuts off returns nothing.
        selected = self.selected = list(testbed.devices)
        results = self.collect_wave(selected)
        record = self.record = CrawlRecord(fence=list(fence), depth=depth, limit=limit)
        logins = {name: () for name in selected}
        gates: dict = {}
        factory_calls = []

        def factory(tb, candidate, via):
            factory_calls.append((candidate.placeholder, candidate.address, candidate.os, via.name))
            if candidate.address in refuse:
                raise collector.CrawlRefused("the proxy cannot be pointed at it")
            device = FakeDevice(candidate.placeholder, candidate.os, candidate.address, proxy=via.connections["cli"].get("proxy"))
            tb.add_device(device)
            return device

        _crawl(
            testbed, POLICY, self.root, datetime.now(timezone.utc), testbed_path, results, selected,
            logins, gates, ("switching",), (), 30, 60, False, "loose", False, False,
            record, parse_fence(fence), self.collect_wave, factory,
        )
        return record, results, selected, factory_calls

    def test_the_switches_a_router_names_are_visited_and_their_own_neighbours_at_the_next_hop(self):
        r1 = FakeDevice("R1", "iosxe", "10.1.0.1", proxy="jump")
        self.neighbours["R1"] = [cdp_entry("SW1", "Gi0/0/1", "10.1.0.11"), cdp_entry("R2", "Gi0/0/2", "10.1.0.2", capabilities="Router")]
        self.neighbours["dev_10_1_0_11"] = [cdp_entry("SW2", "Gi1/0/1", "10.1.0.12"), cdp_entry("R1", "Gi1/0/24", "10.1.0.1", capabilities="Router Switch")]
        self.neighbours["dev_10_1_0_12"] = [cdp_entry("SW3", "Gi1/0/1", "10.1.0.13")]
        self.hostnames = {"dev_10_1_0_11": "SW1", "dev_10_1_0_12": "SW2"}
        record, results, selected, calls = self.run_crawl(FakeTestbed(r1), depth=2)
        self.assertEqual(self.collected, [["R1"], ["dev_10_1_0_11"], ["dev_10_1_0_12"]])
        self.assertEqual([v["name"] for v in record.visited], ["dev_10_1_0_11", "dev_10_1_0_12"])
        self.assertEqual([v["depth"] for v in record.visited], [1, 2])
        self.assertEqual(record.visited[0]["reported_as"], "SW1")
        self.assertEqual(record.visited[0]["via"], "R1")
        self.assertEqual(record.visited[0]["proxy"], "jump")
        # R2 is a router: declined and said so. SW3 is a hop too far: never named as refused, never visited.
        self.assertEqual([(r["name"], r["reason"]) for r in record.refused], [("R2", "does not report the Bridge capability")])
        self.assertEqual(selected, ["R1", "dev_10_1_0_11", "dev_10_1_0_12"])
        self.assertEqual(len(results), 3)
        self.assertEqual(calls[0], ("dev_10_1_0_11", "10.1.0.11", "ios", "R1"))

    def test_a_switch_that_names_the_router_back_or_a_switch_already_visited_is_not_visited_again(self):
        r1 = FakeDevice("R1", "iosxe", "10.1.0.1")
        self.neighbours["R1"] = [cdp_entry("SW1", "Gi0/0/1", "10.1.0.11")]
        # SW1 names R1 by its hostname on a different address, and SW1 itself under a second address.
        self.neighbours["dev_10_1_0_11"] = [cdp_entry("R1", "Gi1/0/24", "10.1.0.99", capabilities="Router Switch"), cdp_entry("SW1", "Gi1/0/2", "10.1.0.111")]
        self.hostnames = {"dev_10_1_0_11": "SW1"}
        record, *_ = self.run_crawl(FakeTestbed(r1), depth=3)
        self.assertEqual([v["name"] for v in record.visited], ["dev_10_1_0_11"])
        # BUG-209: not visited again, and recorded, because a name already
        # taken at an address no device holds can be a second device.
        self.assertEqual(
            [(r["name"], r["address"], r["reason"]) for r in record.refused],
            [("R1", "10.1.0.99", crawl.NAME_TAKEN), ("SW1", "10.1.0.111", crawl.NAME_TAKEN)],
        )

    def test_the_fence_and_the_limit_hold_across_waves(self):
        r1 = FakeDevice("R1", "iosxe", "10.1.0.1")
        self.neighbours["R1"] = [cdp_entry("SW1", "Gi0/0/1", "10.1.0.11"), cdp_entry("SW-FAR", "Gi0/0/2", "10.2.0.11")]
        self.neighbours["dev_10_1_0_11"] = [cdp_entry("SW2", "Gi1/0/1", "10.1.0.12"), cdp_entry("SW3", "Gi1/0/2", "10.1.0.13")]
        record, *_ = self.run_crawl(FakeTestbed(r1), depth=2, limit=2)
        self.assertEqual([v["address"] for v in record.visited], ["10.1.0.11", "10.1.0.12"])
        self.assertEqual({(r["name"], r["reason"]) for r in record.refused},
                         {("SW-FAR", "outside the declared subnets"), ("SW3", "crawl limit reached")})

    def test_a_device_named_in_two_waves_is_declined_once_and_not_at_all_once_visited(self):
        """BUG-289: every wave recorded its own refusal of a device an earlier wave had declined.

        SW-FAR, outside the fence, is named by the router and again by the
        switch the router named. The switch whose proxy could not be pointed
        at it in the first wave is named again in the second and refused
        again. SW-LATE, which the router's report did not identify, is
        identified by the switch's and visited: it was not declined.
        """
        r1 = FakeDevice("R1", "iosxe", "10.1.0.1")
        self.neighbours["R1"] = [
            cdp_entry("SW1", "Gi0/0/1", "10.1.0.11"),
            cdp_entry("SW-FAR", "Gi0/0/2", "10.2.0.11"),
            cdp_entry("SW-WALL", "Gi0/0/3", "10.1.0.30"),
            cdp_entry("SW-LATE", "Gi0/0/4", "10.1.0.40", software="", platform=""),
        ]
        self.neighbours["dev_10_1_0_11"] = [
            cdp_entry("SW-FAR", "Gi1/0/1", "10.2.0.11"),
            cdp_entry("SW-WALL", "Gi1/0/2", "10.1.0.30"),
            cdp_entry("SW-LATE", "Gi1/0/3", "10.1.0.40"),
        ]
        self.hostnames = {"dev_10_1_0_11": "SW1"}
        record, *_ = self.run_crawl(FakeTestbed(r1), depth=2, refuse={"10.1.0.30"})
        self.assertEqual([v["address"] for v in record.visited], ["10.1.0.11", "10.1.0.40"])
        self.assertEqual(
            [(r["name"], r["reason"], r["depth"]) for r in record.refused],
            [("SW-FAR", "outside the declared subnets", 1), ("SW-WALL", "the proxy cannot be pointed at it", 1)],
        )


    def test_a_switch_the_proxy_cannot_reach_is_refused_and_the_rest_of_the_wave_still_visited(self):
        """BUG-257: a device the factory refuses is recorded as refused, and the wave's records stay paired."""
        r1 = FakeDevice("R1", "iosxe", "10.1.0.1")
        self.neighbours["R1"] = [cdp_entry("SW1", "Gi0/0/1", "10.1.0.11"), cdp_entry("SW2", "Gi0/0/2", "10.1.0.12")]
        record, *_ = self.run_crawl(FakeTestbed(r1), depth=1, refuse={"10.1.0.11"})
        self.assertEqual(self.collected, [["R1"], ["dev_10_1_0_12"]])
        self.assertEqual([(v["name"], v["address"]) for v in record.visited], [("dev_10_1_0_12", "10.1.0.12")])
        self.assertEqual(
            [(r["name"], r["address"], r["reason"], r["via"]) for r in record.refused],
            [("SW1", "10.1.0.11", "the proxy cannot be pointed at it", "R1")],
        )

    def test_a_wave_cut_off_keeps_the_record_of_the_switches_it_finished(self):
        """F-39: the visits were recorded once the wave returned, and an interrupted wave never does.

        The finished switch's data was kept and its `crawl.visited` record
        was not, so finalize appended no testbed block for it.
        """
        r1 = FakeDevice("R1", "iosxe", "10.1.0.1")
        self.neighbours["R1"] = [cdp_entry("SW1", "Gi0/0/1", "10.1.0.11"), cdp_entry("SW2", "Gi0/0/2", "10.1.0.12")]
        self.interrupt_at = "dev_10_1_0_12"
        with self.assertRaises(KeyboardInterrupt):
            self.run_crawl(FakeTestbed(r1), depth=1)

        self.assertEqual(self.collected, [["R1"], ["dev_10_1_0_11", "dev_10_1_0_12"]])
        self.assertEqual(
            [(v["name"], v["reported_as"], v["address"], v["depth"]) for v in self.record.visited],
            [("dev_10_1_0_11", "SW1", "10.1.0.11", 1)],
        )

    def test_a_wave_cut_off_names_the_switches_it_never_started_as_not_collected(self):
        """C-06: a wave larger than the worker count was added to `selected` only once it returned.

        The switches planned but not started were withdrawn from the refused
        list when planned and never reached `visited`, so the interrupted
        run's manifest named them nowhere, and its gap list did not say they
        were not collected.
        """
        r1 = FakeDevice("R1", "iosxe", "10.1.0.1")
        self.neighbours["R1"] = [
            cdp_entry("SW1", "Gi0/0/1", "10.1.0.11"), cdp_entry("SW2", "Gi0/0/2", "10.1.0.12"),
            cdp_entry("SW3", "Gi0/0/3", "10.1.0.13"),
        ]
        self.interrupt_at = "dev_10_1_0_12"
        finished: list[DeviceResult] = []
        collect = self.collect_wave

        def wave(names, arrived=None):
            def keep(result):
                finished.append(result)
                if arrived is not None:
                    arrived(result)
            return collect(names, keep)

        self.collect_wave = wave
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.run_crawl(FakeTestbed(r1), depth=1)
        self.assertIn("dev_10_1_0_13", self.selected)

        collector._keep_interrupted_run(
            raised.exception, finished, self.root, datetime.now(timezone.utc), "testbed.yaml", POLICY,
            self.selected, 30, 60, False, (), (), "loose", False, False, self.record,
        )
        manifest = json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["interrupted"]["not_collected"], ["dev_10_1_0_12", "dev_10_1_0_13"])

    def test_the_manifest_records_the_crawl_and_says_so_when_it_was_off(self):
        record = CrawlRecord(fence=["10.1.0.0/24"], depth=2, limit=50)
        record.visited.append({"name": "dev_10_1_0_11", "address": "10.1.0.11"})
        manifest = _build_manifest(self.root, datetime.now(timezone.utc), "tb.yaml", POLICY, ["R1"], [], 30, 60, crawl=record)
        self.assertTrue(manifest["crawl"]["enabled"])
        self.assertEqual(manifest["crawl"]["visited"][0]["address"], "10.1.0.11")
        off = _build_manifest(self.root, datetime.now(timezone.utc), "tb.yaml", POLICY, ["R1"], [], 30, 60)
        self.assertEqual(off["crawl"], {"enabled": False})


class CrawledDeviceFactory(unittest.TestCase):
    def setUp(self):
        self.made = []
        fake_module = types.ModuleType("pyats.topology")

        def Device(name, **kwargs):
            device = SimpleNamespace(name=name, **kwargs)
            self.made.append(device)
            return device

        fake_module.Device = Device
        self._saved = {k: sys.modules.get(k) for k in ("pyats", "pyats.topology")}
        sys.modules["pyats"] = types.ModuleType("pyats")
        sys.modules["pyats.topology"] = fake_module

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value

    def test_the_switch_is_reached_the_way_the_router_that_named_it_is(self):
        via = FakeDevice("R1", "ios", "10.1.0.1", proxy=[{"device": "jump", "command": " ssh 10.1.0.1 admin"}],
                         custom={"double_enable": True}, ssh_options="-o KexAlgorithms=+diffie-hellman-group1-sha1")
        testbed = FakeTestbed(via)
        device = crawled_device(testbed, Candidate("SW1", "10.1.0.11", "ios", "R1"), via)
        self.assertEqual(device.name, "dev_10_1_0_11")
        self.assertEqual(device.os, "ios")
        cli = device.connections["cli"]
        self.assertEqual(cli["ip"], "10.1.0.11")
        self.assertEqual(cli["proxy"], [{"device": "jump", "command": " ssh 10.1.0.11 admin"}])
        self.assertEqual(cli["ssh_options"], "-o KexAlgorithms=+diffie-hellman-group1-sha1")
        self.assertEqual(device.custom, {"double_enable": True})
        self.assertIn("dev_10_1_0_11", testbed.devices)

    def test_the_routers_address_is_replaced_whole_and_never_inside_a_longer_one(self):
        """BUG-257: a substring replace turned the `10.1.0.100` beside the router's `10.1.0.1` into `10.1.0.1100`."""
        via = FakeDevice("R1", "ios", "10.1.0.1", proxy=[{"device": "jump", "command": " ssh -b 10.1.0.100 10.1.0.1 admin"}])
        device = crawled_device(FakeTestbed(via), Candidate("SW1", "10.1.0.11", "ios", "R1"), via)
        self.assertEqual(
            device.connections["cli"]["proxy"], [{"device": "jump", "command": " ssh -b 10.1.0.100 10.1.0.11 admin"}],
        )

    def test_a_hop_that_does_not_name_the_router_by_its_address_is_refused(self):
        """BUG-257: left as it was, the command logs in to the router, and the router is collected as the switch."""
        for command in (" ssh r1 admin", " ssh 10.1.0.10 admin"):
            with self.subTest(command=command):
                via = FakeDevice("R1", "ios", "10.1.0.1", proxy=[{"device": "jump", "command": command}])
                testbed = FakeTestbed(via)
                with self.assertRaises(collector.CrawlRefused):
                    crawled_device(testbed, Candidate("SW1", "10.1.0.11", "ios", "R1"), via)
                self.assertNotIn("dev_10_1_0_11", testbed.devices)

    def test_a_hop_before_the_last_is_how_the_chain_reaches_the_last_and_is_not_the_router(self):
        via = FakeDevice("R1", "ios", "10.1.0.1", proxy=[
            {"device": "jump1", "command": " ssh 192.0.2.9"}, {"device": "jump2", "command": " ssh 10.1.0.1 admin"},
        ])
        device = crawled_device(FakeTestbed(via), Candidate("SW1", "10.1.0.11", "ios", "R1"), via)
        self.assertEqual(device.connections["cli"]["proxy"][1]["command"], " ssh 10.1.0.11 admin")

    def test_login_quirks_are_not_copied_across_an_os_boundary(self):
        via = FakeDevice("R1", "iosxe", "10.1.0.1", proxy="jump", custom={"double_enable": True}, ssh_options="-o X=y")
        device = crawled_device(FakeTestbed(via), Candidate("SW3", "10.1.0.13", "junos", "R1"), via)
        cli = device.connections["cli"]
        self.assertEqual(cli["proxy"], "jump")
        self.assertNotIn("ssh_options", cli)
        self.assertEqual(device.custom, {})


class NoFence(unittest.TestCase):
    def test_a_crawl_with_no_fence_is_refused_before_anything_is_contacted(self):
        # run_collect checks the fence before loading the testbed's devices;
        # the check itself lives in parse_fence returning nothing.
        self.assertEqual(parse_fence([]), [])
        self.assertEqual(parse_fence([""]), [])


class ReviewedCrawlDefects(unittest.TestCase):
    def test_the_iosxe_lldp_shape_names_the_bridge_capability_mac_bridge_and_says_whether_it_is_enabled(self):
        self.assertTrue(bridge_capable({"mac_bridge": {"name": "mac_bridge", "system": True, "enabled": True}}))
        self.assertFalse(bridge_capable({"router": {"system": True, "enabled": True}}))
        # Genie's shape for `System Capabilities: B,R` / `Enabled Capabilities: B`:
        # a capability the box has switched off carries no `enabled` key at all.
        parsed = lldp_state([("GigabitEthernet0/0/2", "ge-0/0/24", {
            "neighbor_id": "EX1", "system_name": "EX1", "port_id": "ge-0/0/24",
            "system_description": "Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 18.4R3",
            "management_address": "10.1.0.13",
            "capabilities": {"mac_bridge": {"name": "mac_bridge", "system": True, "enabled": True}, "router": {"name": "router", "system": True}},
        })])
        [candidate] = lldp_candidates("R1", parsed, depth=1)
        chosen, refused = plan_wave([candidate], parse_fence(["10.1.0.0/24"]), set(), set(), 5)
        self.assertEqual([c.name for c in chosen], ["EX1"])

    def test_a_router_that_could_bridge_but_enabled_only_routing_is_not_a_switch(self):
        """BUG-144: Genie never writes `enabled: False`; it leaves the key out, so System B,R / Enabled R read as a switch."""
        capabilities = {"mac_bridge": {"name": "mac_bridge", "system": True}, "router": {"name": "router", "system": True, "enabled": True}}
        self.assertFalse(bridge_capable(capabilities))
        self.assertFalse(bridge_capable({"bridge": {"system": True}, "router": {"system": True, "enabled": True}}))
        parsed = lldp_state([("GigabitEthernet0/0/2", "Gi0/0/0", {
            "neighbor_id": "R2", "system_name": "R2", "port_id": "Gi0/0/0",
            "system_description": "Cisco IOS Software [Cupertino], ASR1000 Software, Version 17.9.4a",
            "management_address": "10.1.0.2",
            "capabilities": capabilities,
        })])
        [candidate] = lldp_candidates("R1", parsed, depth=1)
        chosen, refused = plan_wave([candidate], parse_fence(["10.1.0.0/24"]), set(), set(), 5)
        self.assertEqual(chosen, [])
        self.assertEqual([(r.name, r.reason) for r in refused], [("R2", "does not report the Bridge capability")])
        # A neighbour whose enabled list was not given is judged by what it says it can do.
        self.assertTrue(bridge_capable({"mac_bridge": {"name": "mac_bridge", "system": True}, "router": {"name": "router", "system": True}}))

    def test_a_junos_box_names_its_neighbours_from_the_text_and_each_is_refused_for_want_of_an_address(self):
        text = (
            "Local Interface    Parent Interface    Chassis Id          Port info          System Name\n"
            "ge-0/0/1           -                   aa:bb:cc:00:05:00   ge-0/0/24          EX5\n"
            "ge-0/0/2           -                   aa:bb:cc:00:06:00   517                EX6\n"
        )
        found = crawl.candidates_from(
            "EX1", lambda device, command: None, CDP_COMMAND, ("show lldp neighbors detail", "show lldp neighbors"), 1,
            raw=lambda device, command: text if command == "show lldp neighbors" else None,
        )
        self.assertEqual([(c.name, c.address, c.via_interface) for c in found], [("EX5", "", "ge-0/0/1"), ("EX6", "", "ge-0/0/2")])
        chosen, refused = plan_wave(found, parse_fence(["10.1.0.0/24"]), set(), set(), 5)
        self.assertEqual(chosen, [])
        self.assertEqual([(r.name, r.reason) for r in refused], [("EX5", "no management address reported"), ("EX6", "no management address reported")])

    def test_a_junos_row_whose_port_info_overruns_its_column_names_the_neighbour_whole(self):
        # The crawl cut each row where the header puts each column, as the
        # topology reader did until BUG-207: a Cisco neighbour's port name is
        # wider than the Port info column, and the cut made a name of its last
        # digit and the neighbour's (`4 SW7`). A neighbour that sent no name
        # is known by its chassis id alone, which the crawl cannot follow.
        text = (
            "Local Interface    Parent Interface    Chassis Id          Port info          System Name\n"
            "ge-0/0/1           -                   aa:bb:cc:00:07:00   GigabitEthernet1/0/24 SW7\n"
            "ge-0/0/2           -                   aa:bb:cc:00:08:00   Port 1 of some long unnamed device\n"
        )
        found = crawl.candidates_from(
            "EX1", lambda device, command: None, CDP_COMMAND, ("show lldp neighbors detail", "show lldp neighbors"), 1,
            raw=lambda device, command: text if command == "show lldp neighbors" else None,
        )
        self.assertEqual([(c.name, c.via_interface) for c in found], [("SW7", "ge-0/0/1")])

    def test_a_junos_row_whose_port_info_overruns_before_a_known_name_names_that_device(self):
        # The topology reads such a row's last word as the name where the
        # snapshot holds a device of it; the crawl reads the table the same
        # way, and a name it holds already is not visited again.
        text = (
            "Local Interface    Parent Interface    Chassis Id          Port info          System Name\n"
            "ge-0/0/2           -                   aa:bb:cc:00:08:00   uplink to the core switch stack sw-1\n"
        )

        def found(known):
            return crawl.candidates_from(
                "EX1", lambda device, command: None, CDP_COMMAND, ("show lldp neighbors detail", "show lldp neighbors"),
                1, raw=lambda device, command: text if command == "show lldp neighbors" else None, known=known,
            )

        self.assertEqual(found(set()), [])
        [candidate] = found({"sw-1", "ex1"})
        self.assertEqual((candidate.name, candidate.via_interface), ("sw-1", "ge-0/0/2"))
        self.assertEqual(plan_wave([candidate], parse_fence(["10.1.0.0/24"]), set(), {"sw-1"}, 5), ([], []))

    def test_the_junos_parse_shape_is_read_too(self):
        parsed = {"lldp-neighbors-information": {"lldp-neighbor-information": [
            {"lldp-local-port-id": "ge-0/0/1", "lldp-remote-system-name": "EX5", "lldp-remote-port-id": "ge-0/0/24"},
        ]}}
        found = crawl.candidates_from("EX1", lambda d, c: parsed if c == "show lldp neighbors" else None, CDP_COMMAND, ("show lldp neighbors detail", "show lldp neighbors"), 1)
        self.assertEqual([(c.name, c.address) for c in found], [("EX5", "")])

    def test_the_nxos_cdp_shape_carries_the_address_under_interface_addresses(self):
        entry = cdp_entry("N9K", "Ethernet1/1", "", software="Cisco Nexus Operating System (NX-OS) Software 9.3(8)")
        entry["interface_addresses"] = {"10.1.0.20": {}}
        [candidate] = cdp_candidates("R1", cdp_state([entry]), depth=1)
        self.assertEqual((candidate.address, candidate.os), ("10.1.0.20", "nxos"))


if __name__ == "__main__":
    unittest.main()
