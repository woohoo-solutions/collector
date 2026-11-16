"""NX-OS multicast in the allowlist (0.3.0, the owner's approval of 16 November 2026).

The first NX-OS field run met an IPTV estate whose allowlist asked nothing
about multicast. Six read-only commands were proposed, each checked as
written against Cisco's Nexus 9000 show-command references for 9.3 and 10.4
and the multicast configuration guides for 9.3 and 10.6.

The three PIM commands exist only once `feature pim` is enabled; a switch
without it rejects them as invalid input. That is the switch saying it runs
no PIM, so it is no collection gap, as `% BGP not active` is none.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from netstate.collector import CommandPolicy, Snapshot, describe_failure
from netstate.platforms import platform_for

MULTICAST = (
    "show ip pim rp vrf all",
    "show ip pim neighbor vrf all",
    "show ip pim interface vrf all",
    "show ip mroute summary vrf all",
    "show ip igmp groups vrf all",
    "show ip igmp snooping groups",
)


class TheAllowlistAsksNxosAboutMulticast(unittest.TestCase):
    def test_the_six_commands_are_the_nxos_multicast_group(self):
        plan = CommandPolicy.load().plan_for("nxos")
        self.assertEqual(plan.feature_commands.get("multicast"), MULTICAST)

    def test_each_is_a_show_command(self):
        for command in MULTICAST:
            with self.subTest(command=command):
                self.assertTrue(command.startswith("show "))

    def test_the_menu_offers_multicast_on_nxos(self):
        self.assertIn("multicast", CommandPolicy.load().features_for("nxos"))


class PimNotEnabledIsNoGap(unittest.TestCase):
    def snapshot(self, os_name, commands):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        devices = {"SW1": {
            "name": "SW1", "os": os_name, "connected": True, "error": None,
            "commands": [
                {"command": c, "status": s, "state_file": None, "raw_file": None,
                 "redacted_lines": 0, "seconds": 1.0, "detail": d}
                for c, s, d in commands
            ],
        }}
        (root / "manifest.json").write_text(json.dumps({
            "disconet_version": "0.1.0", "snapshot_id": "20261116T090000Z",
            "created_at": "2026-11-16T09:00:00+00:00", "devices": devices,
        }), encoding="utf-8")
        return Snapshot.load(root)

    INVALID = "the platform rejected the command as invalid input"

    def test_a_switch_without_feature_pim_reports_no_gap(self):
        snapshot = self.snapshot("nxos", [("show version", "parsed", None)] + [
            (c, "unsupported", self.INVALID) for c in MULTICAST[:3]
        ])
        self.assertEqual(snapshot.gaps(), [])
        for command in MULTICAST[:3]:
            with self.subTest(command=command):
                self.assertTrue(snapshot.feature_not_enabled("SW1", command))

    def test_a_rejected_igmp_or_mroute_command_is_still_a_gap(self):
        # IGMP runs by default and the MRIB without PIM: a rejection there is
        # not the feature being off.
        snapshot = self.snapshot("nxos", [
            ("show version", "parsed", None),
            ("show ip igmp groups vrf all", "unsupported", self.INVALID),
        ])
        self.assertEqual(len(snapshot.gaps()), 1, snapshot.gaps())
        self.assertFalse(snapshot.feature_not_enabled("SW1", "show ip igmp groups vrf all"))

    def test_on_iosxe_a_rejected_pim_command_is_still_a_gap(self):
        snapshot = self.snapshot("iosxe", [
            ("show version", "parsed", None),
            ("show ip pim rp mapping", "unsupported", self.INVALID),
        ])
        self.assertEqual(len(snapshot.gaps()), 1, snapshot.gaps())

    def test_a_pim_command_that_failed_otherwise_is_still_a_gap(self):
        snapshot = self.snapshot("nxos", [
            ("show version", "parsed", None),
            ("show ip pim neighbor vrf all", "failed", "timeout occurred"),
        ])
        self.assertEqual(len(snapshot.gaps()), 1, snapshot.gaps())

    def test_nxos_s_rejection_is_recorded_as_unsupported(self):
        # How an NX-OS switch rejects a command it does not have, as unicon
        # reports it: the status the gap rule above relies on.
        exc = RuntimeError("sub_command failure, patterns matched: ['% Invalid command at '^' marker.']")
        self.assertEqual(describe_failure(exc, 120, False)[0], "unsupported")

    def test_the_registry_names_pim_as_the_gate(self):
        gated = dict(platform_for("nxos").feature_gated)
        self.assertEqual(gated.get("show ip pim"), "pim")


if __name__ == "__main__":
    unittest.main()
