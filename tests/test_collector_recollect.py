"""Targeted re-collect: named commands from named devices, into a partial snapshot.

ARCHITECTURE section 4 of DiscoNet. The narrowing lives in the gate every
other command goes through (`CommandPolicy.plan_for`), the run checks the
request against every OS before anything is contacted, and the manifest
admits the narrowing (`partial`, `requested_commands`, `recollect_of`).
Each device's entry also records when its first command was sent
(`read_at`), and each command when it was sent (`started_at`), so a rate
read at the end of a long run is dated by its own moment, not the run's
start. `Snapshot.read_by` returns that moment.

Public scope: device names are made up, no address appears.
"""

from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netstate import collector
from netstate.collector import (
    REDACTION_MARKER,
    CollectionError,
    CommandNotAllowed,
    CommandPolicy,
    Snapshot,
    _collect_device,
)
from tests.test_collector_enable import OwnTempDirectoryTestCase, RecordingDevice

POLICY = CommandPolicy(
    {
        "iosxr": {
            "parse": ["show version", "show interfaces", "show isis adjacency"],
            "raw_only": ["show running-config"],
            "probe": ["ping {addr}"],
            "features": {
                "isis": {"parse": ["show isis neighbors", "show isis database detail"]},
                "ospf": {"parse": ["show ospf neighbor"]},
            },
        },
        "iosxe": {
            "parse": ["show version", "show interfaces"],
            "raw_only": ["show running-config"],
        },
    }
)


class TheGate(unittest.TestCase):
    """`plan_for(os, commands)`: narrows, never widens. No device needed."""

    def test_a_recollect_narrows_the_plan_to_the_named_commands_in_allowlist_order(self):
        plan = POLICY.plan_for("iosxr", ["show isis neighbors", "show interfaces", "show version"])
        self.assertEqual(plan.parse, ("show version", "show interfaces"))
        self.assertEqual(plan.raw_only, ())
        self.assertEqual(plan.features, (("isis", ("show isis neighbors",)),))
        self.assertEqual(
            plan.selected_parse(None), ("show version", "show interfaces", "show isis neighbors")
        )

    def test_none_is_the_ordinary_plan(self):
        self.assertIs(POLICY.plan_for("iosxr", None), POLICY.plan_for("iosxr"))

    def test_a_recollect_of_no_commands_is_refused_rather_than_sending_nothing(self):
        with self.assertRaisesRegex(CommandNotAllowed, "at least one command"):
            POLICY.plan_for("iosxr", [])

    def test_a_command_outside_the_allowlist_is_refused_before_any_connection(self):
        with self.assertRaisesRegex(CommandNotAllowed, "show clock") as caught:
            POLICY.plan_for("iosxr", ["show version", "show clock"])
        self.assertIn("cannot add a command", str(caught.exception))

    def test_a_command_allowlisted_for_another_os_is_unknown_for_this_one(self):
        with self.assertRaisesRegex(CommandNotAllowed, "show isis adjacency"):
            POLICY.plan_for("iosxe", ["show isis adjacency"])

    def test_command_spelling_is_normalised_the_way_the_send_time_check_normalises_it(self):
        plan = POLICY.plan_for("iosxr", ["  SHOW   Interfaces "])
        self.assertEqual(plan.parse, ("show interfaces",))
        self.assertEqual(POLICY.assert_allowed("iosxr", "  SHOW   Interfaces "), "  SHOW   Interfaces ")

    def test_a_narrowed_plan_carries_no_probes(self):
        self.assertTrue(POLICY.plan_for("iosxr").probe)
        self.assertEqual(POLICY.plan_for("iosxr", ["show version"]).probe, ())

    def test_a_narrowed_plan_keeps_only_the_feature_groups_that_still_hold_a_command(self):
        plan = POLICY.plan_for("iosxr", ["show isis database detail"])
        self.assertEqual(plan.features, (("isis", ("show isis database detail",)),))
        self.assertEqual(plan.parse, ())

    def test_a_raw_only_command_can_be_named(self):
        plan = POLICY.plan_for("iosxr", ["show running-config"])
        self.assertEqual((plan.parse, plan.raw_only), ((), ("show running-config",)))


class TheShippedAllowlist(unittest.TestCase):
    """The commands `disconet sample` names, on each OS it reads counters from."""

    def test_every_counter_command_is_on_its_os_allowlist(self):
        policy = CommandPolicy.load()
        for os_name, command in (
            ("ios", "show interfaces"),
            ("iosxe", "show interfaces"),
            ("iosxr", "show interfaces"),
            ("nxos", "show interface"),
            ("junos", "show interfaces extensive"),
        ):
            with self.subTest(os=os_name):
                self.assertEqual(policy.plan_for(os_name, [command]).parse, (command,))


# A hand-written `show interfaces extensive` from Junos, cut to one physical
# interface; the MAC is from the documentation range (RFC 7042).
JUNOS_EXTENSIVE = """\
Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Interface index: 148, SNMP ifIndex: 526, Generation: 151
  Link-level type: Ethernet, MTU: 1514, MRU: 1522, LAN-PHY mode, Speed: 1000mbps, BPDU Error: None, Loop Detect PDU Error: None,
  Ethernet-Switching Error: None, MAC-REWRITE Error: None, Loopback: Disabled, Source filtering: Disabled, Flow control: Enabled,
  Auto-negotiation: Enabled, Remote fault: Online
  Device flags   : Present Running
  Interface flags: SNMP-Traps Internal: 0x4000
  Link flags     : None
  CoS queues     : 8 supported, 8 maximum usable queues
  Hold-times     : Up 0 ms, Down 0 ms
  Current address: 00:00:5e:00:53:01, Hardware address: 00:00:5e:00:53:01
  Last flapped   : 2026-11-01 09:12:44 UTC (2w3d 20:47 ago)
  Statistics last cleared: Never
  Traffic statistics:
   Input  bytes  :         918263741552             41255328 bps
   Output bytes  :         771180020210             32550616 bps
   Input  packets:            901212773                 4511 pps
   Output packets:            816002113                 3987 pps
   IPv6 transit statistics:
    Input  bytes  :                    0
    Output bytes  :                    0
    Input  packets:                    0
    Output packets:                    0
"""


class TheJunosCounterCommand(unittest.TestCase):
    def test_genie_reads_the_byte_counters_and_rates_of_show_interfaces_extensive(self):
        from genie.libs.parser.junos.show_interface import ShowInterfacesExtensive

        parsed = ShowInterfacesExtensive(device=mock.Mock()).parse(output=JUNOS_EXTENSIVE)
        [interface] = parsed["interface-information"]["physical-interface"]
        traffic = interface["traffic-statistics"]
        self.assertEqual(interface["name"], "ge-0/0/0")
        self.assertEqual((traffic["input-bytes"], traffic["output-bytes"]), ("918263741552", "771180020210"))
        self.assertEqual((traffic["input-bps"], traffic["output-bps"]), ("41255328", "32550616"))


class OneDevice(OwnTempDirectoryTestCase):
    """`_collect_device` with a narrowed plan, against a device that records what it was sent."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def device(self, **kwargs):
        device = RecordingDevice(os_name="iosxr", credentials={}, **kwargs)
        device.name = "zz-lab-pe1"
        return device

    @staticmethod
    def shows(device) -> list[str]:
        return [command for command in device.commands if command.startswith("show ")]

    def test_recollect_sends_exactly_the_named_commands_and_nothing_else(self):
        device = self.device()
        outcome = _collect_device(
            device, POLICY, self.root, commands=["show isis neighbors", "show interfaces"],
            verify_reachability=True,
        )
        self.assertIsNone(outcome.error)
        self.assertEqual(self.shows(device), ["show interfaces", "show isis neighbors"])
        self.assertFalse(any(command.startswith("ping") for command in device.commands))
        files = sorted(p.relative_to(self.root / "zz-lab-pe1").as_posix()
                       for p in (self.root / "zz-lab-pe1").rglob("*") if p.is_file() and "raw" in p.parts)
        self.assertEqual(files, ["raw/show_interfaces.txt", "raw/show_isis_neighbors.txt"])

    def test_recollect_goes_through_the_same_redaction(self):
        secret = "snmp-server community Zx9-hidden-word RO"
        device = self.device(outputs={"show running-config": f"hostname zz-lab-pe1\n{secret}\n"})
        _collect_device(device, POLICY, self.root, commands=["show running-config"])
        raw = (self.root / "zz-lab-pe1" / "raw" / "show_running_config.txt").read_text(encoding="utf-8")
        self.assertNotIn("Zx9-hidden-word", raw)
        self.assertIn(REDACTION_MARKER, raw)

    def test_every_command_records_when_it_was_sent_and_the_device_its_first(self):
        before = datetime.now(timezone.utc)
        outcome = _collect_device(self.device(), POLICY, self.root, commands=["show version", "show interfaces"])
        after = datetime.now(timezone.utc)
        moments = [datetime.fromisoformat(c.started_at) for c in outcome.commands]
        self.assertEqual(len(moments), 2)
        for moment in moments:
            self.assertEqual(moment.utcoffset(), timedelta(0))
            self.assertTrue(before <= moment <= after)
        self.assertLessEqual(moments[0], moments[1])
        entry = outcome.as_dict()
        self.assertEqual(entry["read_at"], outcome.commands[0].started_at)
        self.assertEqual([c["started_at"] for c in entry["commands"]], [c.started_at for c in outcome.commands])

    def test_a_retry_after_a_timeout_is_dated_by_the_attempt_that_answered(self):
        device = self.device(fail_once={"show interfaces"})
        with mock.patch.object(collector, "RETRY_PAUSE", 0), \
                mock.patch.object(collector.time, "sleep"):
            clock = iter(datetime(2026, 11, 18, 6, 0, s, tzinfo=timezone.utc) for s in range(0, 60))
            real = collector.datetime

            class Clock(real):
                @classmethod
                def now(cls, tz=None):
                    return next(clock)

            with mock.patch.object(collector, "datetime", Clock):
                outcome = _collect_device(device, POLICY, self.root, commands=["show interfaces"])
        [result] = outcome.commands
        self.assertEqual(result.status, "parsed")
        self.assertEqual(self.shows(device), ["show interfaces", "show interfaces"])
        # The first attempt was sent at one moment and timed out; the answer
        # kept is the second attempt's, sent later.
        self.assertGreater(result.started_at, "2026-11-18T06:00:01+00:00")

    def test_a_device_whose_os_a_per_os_recollect_does_not_name_is_never_contacted(self):
        device = self.device()
        outcome = _collect_device(device, POLICY, self.root, commands={"iosxe": ["show interfaces"]})
        self.assertEqual(device.commands, [])
        self.assertFalse(outcome.connected)
        self.assertIn("not asked", outcome.error)

    def test_a_device_never_reached_has_no_read_moment(self):
        device = self.device(connect_errors=[ConnectionError("refused")] * 3)
        outcome = _collect_device(device, POLICY, self.root, commands=["show interfaces"])
        self.assertFalse(outcome.connected)
        self.assertIsNone(outcome.read_at)
        self.assertNotIn("read_at", outcome.as_dict())


class Runs(OwnTempDirectoryTestCase):
    """A whole `run_collect` / `run_recollect`, pyATS stood in for."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name) / "snapshots"
        self.testbed_path = Path(tmp.name) / "testbed.yaml"
        self.testbed_path.write_text("devices: {}\n", encoding="utf-8")
        self.commands_file = Path(tmp.name) / "commands.yaml"
        self.commands_file.write_text(
            "iosxr:\n  parse:\n    - show version\n    - show interfaces\n    - show isis adjacency\n"
            "iosxe:\n  parse:\n    - show version\n    - show interfaces\n",
            encoding="utf-8",
        )
        devices = {
            "zz-lab-pe1": SimpleNamespace(name="zz-lab-pe1", os="iosxr", connections={}, custom={}, credentials={}),
            "zz-lab-ce1": SimpleNamespace(name="zz-lab-ce1", os="iosxe", connections={}, custom={}, credentials={}),
        }
        self.testbed = SimpleNamespace(devices=devices)
        genie = types.ModuleType("genie")
        genie_testbed = types.ModuleType("genie.testbed")
        genie_testbed.load = lambda path: self.testbed
        modules = mock.patch.dict(sys.modules, {"genie": genie, "genie.testbed": genie_testbed})
        modules.start()
        self.addCleanup(modules.stop)
        self.calls: list[tuple[str, object]] = []

    def collect_device(self, device, *args, **kwargs):
        self.calls.append((device.name, kwargs.get("commands")))
        result = collector.DeviceResult(name=device.name, os=device.os, connected=True)
        moment = {"zz-lab-pe1": "2026-11-18T06:00:05+00:00", "zz-lab-ce1": "2026-11-18T06:31:40+00:00"}[device.name]
        result.commands.append(collector.CommandResult(command="show interfaces", status="parsed", started_at=moment))
        return result

    def go(self, recollect=True, **kwargs):
        with mock.patch.object(collector, "_collect_device", side_effect=self.collect_device), \
                mock.patch.object(collector, "record_snapshot"):
            if recollect:
                return collector.run_recollect(
                    self.testbed_path, base_dir=self.base, commands_file=self.commands_file, workers=1, **kwargs,
                )
            return collector.run_collect(
                self.testbed_path, base_dir=self.base, commands_file=self.commands_file, workers=1, **kwargs,
            )

    def written(self) -> dict:
        [root] = list(self.base.iterdir())
        return json.loads((root / "manifest.json").read_text(encoding="utf-8"))

    def test_recollect_writes_a_partial_manifest_naming_the_commands(self):
        manifest = self.go(devices=["zz-lab-pe1", "zz-lab-ce1"], commands=["show interfaces"],
                            recollect_of="20261117T200000Z")
        self.assertIs(manifest["partial"], True)
        self.assertEqual(manifest["requested_commands"], ["show interfaces"])
        self.assertEqual(manifest["recollect_of"], "20261117T200000Z")
        self.assertEqual(self.written()["partial"], True)
        self.assertEqual({name: commands for name, commands in self.calls},
                         {"zz-lab-pe1": ["show interfaces"], "zz-lab-ce1": ["show interfaces"]})

    def test_an_ordinary_collect_writes_partial_false_and_no_requested_commands(self):
        manifest = self.go(recollect=False)
        self.assertIs(manifest["partial"], False)
        self.assertEqual(manifest["requested_commands"], [])
        self.assertEqual(manifest["recollect_of"], "")
        self.assertEqual({commands for _, commands in self.calls}, {None})

    def test_recollect_validates_every_os_before_the_pool_starts(self):
        with self.assertRaisesRegex(CommandNotAllowed, "iosxe.*show isis adjacency"):
            self.go(devices=["zz-lab-pe1", "zz-lab-ce1"], commands=["show isis adjacency"])
        self.assertEqual(self.calls, [])
        self.assertFalse(self.base.exists() and any(self.base.iterdir()))

    def test_recollect_requires_a_device_and_a_command(self):
        for devices, commands in (([], ["show interfaces"]), (["zz-lab-pe1"], [])):
            with self.subTest(devices=devices, commands=commands):
                with self.assertRaisesRegex(CollectionError, "at least one device and at least one command"):
                    self.go(devices=devices, commands=commands)
        self.assertEqual(self.calls, [])

    def test_recollect_refuses_the_options_it_pins(self):
        with self.assertRaisesRegex(CollectionError, "verify_reachability"):
            self.go(devices=["zz-lab-pe1"], commands=["show interfaces"], verify_reachability=True)

    def test_a_command_list_per_os_sends_each_device_its_own(self):
        manifest = self.go(
            devices=["zz-lab-pe1", "zz-lab-ce1"],
            commands={"iosxr": ["show interfaces"], "iosxe": ["show version", "show interfaces"]},
        )
        self.assertEqual(dict(self.calls)["zz-lab-pe1"], {"iosxr": ["show interfaces"],
                                                         "iosxe": ["show version", "show interfaces"]})
        # Allowlist order within each OS, the OSes in name order: reproducible.
        self.assertEqual(manifest["requested_commands"], ["show version", "show interfaces"])
        self.assertIs(manifest["partial"], True)

    def test_a_command_list_per_os_is_checked_per_os_before_the_pool_starts(self):
        with self.assertRaisesRegex(CommandNotAllowed, "iosxe.*show isis adjacency"):
            self.go(devices=["zz-lab-pe1", "zz-lab-ce1"],
                    commands={"iosxr": ["show isis adjacency"], "iosxe": ["show isis adjacency"]})
        self.assertEqual(self.calls, [])

    def test_commands_for_reads_one_list_or_the_os_entry_and_refuses_an_os_not_named(self):
        self.assertIsNone(collector.commands_for(None, "iosxe"))
        self.assertEqual(collector.commands_for(["show interfaces"], "iosxe"), ["show interfaces"])
        self.assertEqual(collector.commands_for({"nxos": ["show interface"]}, "nxos"), ["show interface"])
        with self.assertRaisesRegex(collector.NotAsked, "names no command for os 'asa'"):
            collector.commands_for({"nxos": ["show interface"]}, "asa")

    def test_each_device_is_dated_by_its_own_read_not_the_run_start(self):
        manifest = self.go(devices=["zz-lab-pe1", "zz-lab-ce1"], commands=["show interfaces"])
        [root] = list(self.base.iterdir())
        snapshot = Snapshot.load(root)
        self.assertEqual(snapshot.read_by("zz-lab-pe1"), (manifest["snapshot_id"], "2026-11-18T06:00:05+00:00"))
        self.assertEqual(snapshot.read_by("zz-lab-ce1"), (manifest["snapshot_id"], "2026-11-18T06:31:40+00:00"))

    def test_a_run_cut_short_keeps_the_partial_mark(self):
        def collect_device(device, *args, **kwargs):
            if device.name == "zz-lab-pe1":
                return self.collect_device(device, *args, **kwargs)
            raise KeyboardInterrupt

        with mock.patch.object(collector, "_collect_device", side_effect=collect_device), \
                mock.patch.object(collector, "record_snapshot"):
            with self.assertRaises(KeyboardInterrupt):
                collector.run_recollect(
                    self.testbed_path, ["zz-lab-pe1", "zz-lab-ce1"], ["show interfaces"],
                    base_dir=self.base, commands_file=self.commands_file, workers=1,
                )
        manifest = self.written()
        self.assertIn("interrupted", manifest)
        self.assertIs(manifest["partial"], True)
        self.assertEqual(manifest["requested_commands"], ["show interfaces"])


class TheReaders(unittest.TestCase):
    def snapshot(self, manifest: dict) -> Snapshot:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / manifest.get("snapshot_id", "20261118T060000Z")
        root.mkdir()
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return Snapshot.load(root)

    def test_snapshot_reports_partial_and_the_requested_commands(self):
        snapshot = self.snapshot({
            "snapshot_id": "20261118T060000Z", "created_at": "2026-11-18T06:00:00+00:00",
            "partial": True, "requested_commands": ["show interfaces"], "recollect_of": "20261117T200000Z",
            "devices": {},
        })
        self.assertTrue(snapshot.partial)
        self.assertEqual(snapshot.requested_commands, ("show interfaces",))
        self.assertEqual(snapshot.recollect_of, "20261117T200000Z")

    def test_a_manifest_written_before_0_4_reads_as_whole(self):
        snapshot = self.snapshot({"snapshot_id": "20260901T060000Z", "created_at": "2026-09-01T06:00:00+00:00",
                                  "devices": {"zz-lab-pe1": {"connected": True, "commands": []}}})
        self.assertFalse(snapshot.partial)
        self.assertEqual(snapshot.requested_commands, ())
        self.assertEqual(snapshot.recollect_of, "")
        # And its devices are dated by the run's start, as they always were.
        self.assertEqual(snapshot.read_by("zz-lab-pe1"), ("20260901T060000Z", "2026-09-01T06:00:00+00:00"))


if __name__ == "__main__":
    unittest.main()
