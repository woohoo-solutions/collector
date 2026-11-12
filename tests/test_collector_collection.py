"""Collection logic, exercised against a fake device.

Covers the execute-once-then-parse path, the unparsed fallback, redaction on
the way to disk and the read-only gate, without contacting any hardware.
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netstate import collector
from netstate.collector import (
    REDACTION_MARKER,
    CommandNotAllowed,
    CommandPolicy,
    Snapshot,
    _collect_command,
    describe_failure,
    summarise_error,
)
from tests.test_collector_enable import OwnTempDirectoryTestCase, RecordingDevice

POLICY = CommandPolicy(
    {
        "iosxe": {
            "parse": ["show version", "show ip ospf neighbor"],
            "raw_only": ["show running-config"],
        }
    }
)


class SchemaEmptyParserError(Exception):
    """Stand-in for the Genie exception, matched by class name."""


class ParserNotFound(Exception):
    """Stand-in for the Genie exception."""


class FakeDevice:
    """Minimal stand-in for a Genie device.

    ``raw`` maps command -> raw output (or an Exception to raise).
    ``parsed`` maps command -> parse result (or an Exception to raise).
    """

    def __init__(self, raw=None, parsed=None):
        self.name = "R1"
        self.os = "iosxe"
        self._raw = raw or {}
        self._parsed = parsed or {}
        self.executed: list[str] = []
        self.execute_timeouts: list[int | None] = []
        self.parsed_from_output: list[tuple[str, str | None]] = []

    def execute(self, command, timeout=None):
        self.executed.append(command)
        self.execute_timeouts.append(timeout)
        result = self._raw.get(command, f"<output of {command}>")
        if isinstance(result, Exception):
            raise result
        return result

    def parse(self, command, output=None):
        # Genie is always called with pre-captured output so the device is
        # touched once per command; record it so tests can assert that.
        self.parsed_from_output.append((command, output))
        result = self._parsed.get(command)
        if isinstance(result, Exception):
            raise result
        if result is None:
            raise ParserNotFound(f"no parser for {command}")
        return result


class FlakyDevice(FakeDevice):
    """Fails the first execution of a command, then answers normally.

    This is what a virtual router looks like when a burst of console logging
    swallows the first answer: the session is fine, the command is fine, the
    timing was not.
    """

    def __init__(self, failures=1, error=None, **kwargs):
        super().__init__(**kwargs)
        self.remaining = failures
        self.error = error or TimeoutError("timeout occurred: timeout value: 120")

    def execute(self, command, timeout=None):
        if self.remaining:
            self.remaining -= 1
            self.executed.append(command)
            self.execute_timeouts.append(timeout)
            raise self.error
        return super().execute(command, timeout=timeout)


class CollectCommandTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.snapshot_root = Path(self._tmp.name)
        # The real pause between attempts is seconds; tests should not wait.
        self._pause = collector.RETRY_PAUSE
        collector.RETRY_PAUSE = 0

    def tearDown(self):
        collector.RETRY_PAUSE = self._pause
        self._tmp.cleanup()

    def collect(self, device, command="show version", parse=True, timeout=120):
        return _collect_command(
            device, "iosxe", command, POLICY, self.snapshot_root, "R1", parse, timeout
        )

    def read(self, relative):
        return (self.snapshot_root / relative).read_text(encoding="utf-8")


class TestExecuteOnceThenParse(CollectCommandTestCase):
    def test_the_parser_reads_the_redacted_text_so_no_secret_reaches_the_state_file(self):
        device = FakeDevice(
            raw={"show version": "hostname R1\nenable secret 5 $1$abcd$KJhgFDsaQwErTy123\n"},
            parsed={"show version": {"version": {"hostname": "R1"}}},
        )
        result = self.collect(device)
        [(command, output)] = device.parsed_from_output
        self.assertEqual(command, "show version")
        self.assertNotIn("KJhgFDsaQwErTy123", output)
        self.assertIn(collector.REDACTION_MARKER, output)
        self.assertEqual(result.redacted_lines, 1)

    def test_parse_reuses_captured_output_instead_of_rerunning(self):
        device = FakeDevice(
            raw={"show version": "Cisco IOS XE Software, Version 17.03.04a"},
            parsed={"show version": {"version": {"version": "17.03.04a"}}},
        )
        result = self.collect(device)

        # Exactly one execution, and the parser was fed that same text — the
        # raw file and the structured state describe one sample, not two.
        self.assertEqual(device.executed, ["show version"])
        self.assertEqual(
            device.parsed_from_output,
            [("show version", "Cisco IOS XE Software, Version 17.03.04a")],
        )
        self.assertEqual(result.status, "parsed")

    def test_parsed_state_and_raw_are_both_written(self):
        device = FakeDevice(
            raw={"show version": "Cisco IOS XE Software, Version 17.03.04a"},
            parsed={"show version": {"version": {"version": "17.03.04a"}}},
        )
        result = self.collect(device)

        self.assertEqual(result.state_file, "R1/state/show_version.json")
        self.assertEqual(result.raw_file, "R1/raw/show_version.txt")
        self.assertEqual(
            json.loads(self.read(result.state_file)), {"version": {"version": "17.03.04a"}}
        )
        self.assertIn("17.03.04a", self.read(result.raw_file))

    def test_command_timeout_is_applied(self):
        """Slow virtual routers time out mid-command otherwise."""
        device = FakeDevice()
        self.collect(device, timeout=300)
        self.assertEqual(device.execute_timeouts, [300])


class TestDegradation(CollectCommandTestCase):
    def test_no_parser_keeps_raw_and_flags_unparsed(self):
        device = FakeDevice(raw={"show version": "some unparseable text"})
        result = self.collect(device)

        self.assertEqual(result.status, "unparsed")
        self.assertIsNone(result.state_file)
        self.assertEqual(self.read(result.raw_file).strip(), "some unparseable text")
        self.assertIn("ParserNotFound", result.detail)

    def test_empty_output_is_recorded_as_a_fact_not_a_failure(self):
        # "no OSPF neighbours" is itself worth documenting.
        device = FakeDevice(
            parsed={"show ip ospf neighbor": SchemaEmptyParserError("empty output")}
        )
        result = self.collect(device, command="show ip ospf neighbor")

        self.assertEqual(result.status, "empty")
        self.assertEqual(json.loads(self.read(result.state_file)), {})

    def test_dead_command_does_not_abort_the_device(self):
        device = FakeDevice(raw={"show version": RuntimeError("device hung")})
        result = self.collect(device)

        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.raw_file)
        self.assertIsNone(result.state_file)
        self.assertIn("RuntimeError", result.detail)


class TestAPrivilegeRefusalIsNotAPlatformGap(CollectCommandTestCase):
    """BUG-255: every device of an OS has its configuration and `show version`.

    One that calls either invalid input is refusing it to an unprivileged
    session (`show running-config` at privilege 1), and 'not supported on
    3 device(s)' sent the reader to the platform instead of the login.
    """

    INVALID = RuntimeError("sub_command failure, patterns matched: % Invalid input detected at '^' marker.")

    def test_the_configuration_refused_as_invalid_input_says_privilege(self):
        for command in ("show running-config", "show version"):
            with self.subTest(command=command):
                result = self.collect(FakeDevice(raw={command: self.INVALID}), command=command, parse=False)
                self.assertEqual(result.status, "failed")
                self.assertIn("unprivileged", result.detail)
                self.assertIn("double_enable", result.detail)

    def test_any_other_command_refused_as_invalid_input_is_still_unsupported(self):
        result = self.collect(FakeDevice(raw={"show ip ospf neighbor": self.INVALID}), command="show ip ospf neighbor")
        self.assertEqual(result.status, "unsupported")


class TestTransientFailures(CollectCommandTestCase):
    """A virtual router that loses one answer has not failed the collection."""

    TIMEOUT = TimeoutError(
        "timeout occurred:\n  timeout value: 120\n  last_command: 'show version\\r'\n"
        "  pattern: ['^.*\\\\[confirm\\\\]\\\\s*[\\\\(\\\\[]y/n[\\\\]\\\\)].*$']"
    )

    def test_a_timed_out_command_is_retried_once_and_recovers(self):
        device = FlakyDevice(
            raw={"show version": "Cisco IOS XE Software, Version 17.03.04a"},
            parsed={"show version": {"version": {"version": "17.03.04a"}}},
        )
        result = self.collect(device)

        self.assertEqual(result.status, "parsed")
        self.assertEqual(device.executed, ["show version", "show version"])

    def test_the_retry_sends_the_same_allowlisted_command_and_no_other(self):
        device = FlakyDevice(raw={"show version": "output"})
        self.collect(device)
        self.assertEqual(set(device.executed), {"show version"})

    def test_a_command_that_keeps_timing_out_gives_up(self):
        device = FakeDevice(raw={"show version": self.TIMEOUT})
        result = self.collect(device)

        self.assertEqual(result.status, "failed")
        # Two attempts, then the failure is reported rather than retried forever.
        self.assertEqual(device.executed, ["show version", "show version"])

    def test_a_timeout_is_reported_in_words_not_as_a_unicon_traceback(self):
        device = FakeDevice(raw={"show version": self.TIMEOUT})
        result = self.collect(device)

        self.assertEqual(
            result.detail, "no prompt within 120s — the device did not finish answering"
        )
        self.assertNotIn("pattern:", result.detail)

    def test_an_unsupported_command_is_not_a_failure_and_is_not_retried(self):
        # IOS-XRv 9000 has no `show inventory`. That is a platform fact. Not
        # `show version`, which every device has (BUG-255).
        device = FakeDevice(
            raw={
                "show ip ospf neighbor": RuntimeError(
                    "sub_command failure: show ip ospf neighbor\r\n"
                    "% Invalid input detected at '^' marker."
                )
            }
        )
        result = self.collect(device, command="show ip ospf neighbor")

        self.assertEqual(result.status, "unsupported")
        self.assertEqual(device.executed, ["show ip ospf neighbor"])
        self.assertIn("invalid input", result.detail)

    def test_classification_of_the_real_error_shapes(self):
        cases = [
            (self.TIMEOUT, "failed"),
            (RuntimeError("% Invalid input detected at '^' marker."), "unsupported"),
            (RuntimeError("% Incomplete command."), "unsupported"),
            (RuntimeError("connection reset by peer"), "failed"),
        ]
        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                status, detail = describe_failure(error, 120)
                self.assertEqual(status, expected)
                self.assertTrue(detail)

    def test_a_long_traceback_is_collapsed_to_one_scannable_line(self):
        summary = summarise_error(RuntimeError("a\n   b\t\tc " + "x" * 400))
        self.assertLessEqual(len(summary), 161)
        self.assertNotIn("\n", summary)
        self.assertIn("RuntimeError: a b c", summary)


class Reopen:
    """Records each reopen and answers from a script, True once the script runs out."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.answers.pop(0) if self.answers else True


class TestTheSessionAfterAFinalTimeout(CollectCommandTestCase):
    """BUG-112: the answer that timed out is still arriving, so the next command starts on a fresh session.

    Without a reopen the tail of that answer was read as the next command's
    output and written into its raw and state files.
    """

    TIMEOUT = TimeoutError("timeout occurred: timeout value: 120")

    def test_a_command_that_keeps_timing_out_is_followed_by_a_reopen(self):
        device = FakeDevice(raw={"show version": self.TIMEOUT})
        reopen = Reopen()
        result = _collect_command(
            device, "iosxe", "show version", POLICY, self.snapshot_root, "R1", True, 120, reopen,
        )
        self.assertEqual(result.status, "failed")
        # One for the retry, one after the attempt that gave up.
        self.assertEqual(reopen.calls, 2)

    def test_a_reopen_that_fails_after_the_last_attempt_is_said(self):
        device = FakeDevice(raw={"show version": self.TIMEOUT})
        result = _collect_command(
            device, "iosxe", "show version", POLICY, self.snapshot_root, "R1", True, 120, Reopen(True, False),
        )
        self.assertIn("reconnecting after it failed", result.detail)

    def test_a_failure_that_is_not_a_timeout_needs_no_reopen(self):
        device = FakeDevice(raw={"show version": RuntimeError("% Invalid input detected at '^' marker.")})
        reopen = Reopen()
        _collect_command(device, "iosxe", "show version", POLICY, self.snapshot_root, "R1", True, 120, reopen)
        self.assertEqual(reopen.calls, 0)

    def per_vrf(self, device, reopen):
        config = self.snapshot_root / "R1" / "raw" / "show_running-config.txt"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("vrf definition RED\n!\nvrf definition BLUE\n!\n", encoding="utf-8")
        policy = CommandPolicy({"iosxe": {
            "parse": ["show version"], "raw_only": ["show running-config"], "per_vrf": ["show ip arp vrf {vrf}"],
        }})
        collected = [collector.CommandResult(
            command="show running-config", status="raw", raw_file="R1/raw/show_running-config.txt",
        )]
        return collector._collect_per_vrf(
            device, "iosxe", policy, self.snapshot_root, "R1", collected, 120, reopen_session=reopen,
        )

    def test_a_per_vrf_table_that_times_out_is_followed_by_a_reopen(self):
        device = FakeDevice(raw={"show ip arp vrf RED": self.TIMEOUT})
        reopen = Reopen()
        results = self.per_vrf(device, reopen)
        self.assertEqual(reopen.calls, 1)
        self.assertEqual(device.executed, ["show ip arp vrf RED", "show ip arp vrf BLUE"])
        self.assertEqual([result.status for result in results], ["failed", "unparsed"])

    def test_the_per_vrf_tables_stop_when_the_session_cannot_be_reopened(self):
        device = FakeDevice(raw={"show ip arp vrf RED": self.TIMEOUT})
        results = self.per_vrf(device, Reopen(False))
        self.assertEqual(device.executed, ["show ip arp vrf RED"])
        self.assertEqual([result.command for result in results], ["show ip arp vrf RED", "show ip arp vrf BLUE"])
        self.assertEqual(results[1].status, "failed")
        self.assertIn("not sent", results[1].detail)

    def probe(self, device, reopen):
        arp = self.snapshot_root / "R1" / "state" / "show_ip_arp.json"
        arp.parent.mkdir(parents=True, exist_ok=True)
        arp.write_text(json.dumps({"interfaces": {"GigabitEthernet2": {"ipv4": {"neighbors": {
            address: {"ip": address, "origin": "dynamic"} for address in ("10.0.12.2", "10.0.12.3")
        }}}}}), encoding="utf-8")
        policy = CommandPolicy({"iosxe": {"parse": ["show ip arp"], "probe": ["ping {addr}"]}})
        collected = [collector.CommandResult(command="show ip arp", status="parsed", state_file="R1/state/show_ip_arp.json")]
        return collector._probe_device(
            device, "iosxe", policy, self.snapshot_root, "R1", collected, 20, 10, reopen_session=reopen,
        )

    def test_a_probe_that_times_out_is_followed_by_a_reopen(self):
        device = FakeDevice(raw={"ping 10.0.12.2": self.TIMEOUT})
        reopen = Reopen()
        self.probe(device, reopen)
        self.assertEqual(reopen.calls, 1)
        self.assertEqual(device.executed, ["ping 10.0.12.2", "ping 10.0.12.3"])

    def test_probing_stops_when_the_session_cannot_be_reopened(self):
        device = FakeDevice(raw={"ping 10.0.12.2": self.TIMEOUT})
        results = self.probe(device, Reopen(False))
        # The neighbour not pinged stays 'not probed' rather than 'unreachable'.
        self.assertEqual(device.executed, ["ping 10.0.12.2"])
        self.assertEqual([result.command for result in results], ["ping 10.0.12.2"])


class TestVrfsWhoseTablesAreNotRead(CollectCommandTestCase):
    """BUG-254: a VRF whose tables are not read is recorded, not dropped in silence.

    One past the limit of VRFs a device is read for, or one whose name holds a
    character no per-VRF command is rendered with, left no trace but a log
    line: the ARP links in it were simply absent, with no gap to say so.
    """

    POLICY = CommandPolicy({"iosxe": {
        "parse": ["show version"], "raw_only": ["show running-config"], "per_vrf": ["show ip arp vrf {vrf}"],
    }})

    def per_vrf(self, config, **kwargs):
        path = self.snapshot_root / "R1" / "raw" / "show_running-config.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(config, encoding="utf-8")
        collected = [collector.CommandResult(
            command="show running-config", status="raw", raw_file="R1/raw/show_running-config.txt",
        )]
        device = FakeDevice()
        not_read: dict[str, str] = {}
        collector._collect_per_vrf(
            device, "iosxe", self.POLICY, self.snapshot_root, "R1", collected, 120, not_read=not_read, **kwargs,
        )
        return device, not_read

    def test_the_vrfs_past_the_limit_are_recorded(self):
        device, not_read = self.per_vrf(
            "vrf definition RED\n!\nvrf definition BLUE\n!\nvrf definition GREEN\n!\n", vrf_limit=1,
        )
        self.assertEqual(device.executed, ["show ip arp vrf RED"])
        self.assertEqual(list(not_read), ["BLUE", "GREEN"])
        self.assertEqual(not_read["BLUE"], collector.VRF_LIMIT_REACHED.format(limit=1))

    def test_a_vrf_whose_name_cannot_be_sent_is_recorded_and_never_sent(self):
        device, not_read = self.per_vrf("vrf definition RED\n!\nvrf definition CUST/B\n!\n")
        self.assertEqual(device.executed, ["show ip arp vrf RED"])
        self.assertEqual(not_read, {"CUST/B": collector.VRF_NAME_REFUSED})

    def test_the_manifest_carries_them_only_where_there_are_any(self):
        result = collector.DeviceResult(name="R1", os="iosxe", connected=True)
        self.assertNotIn("vrfs_not_read", result.as_dict())
        result.vrfs_not_read["BLUE"] = "why"
        self.assertEqual(result.as_dict()["vrfs_not_read"], {"BLUE": "why"})

    def test_the_gap_list_counts_them_by_reason_and_names_none(self):
        # A name the rendering refused is one the rest of the tool may not
        # know as a VRF either, so the gap line, which reaches the document,
        # carries the count; the manifest has the names.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        refused, over = collector.VRF_NAME_REFUSED, collector.VRF_LIMIT_REACHED.format(limit=250)
        (root / "manifest.json").write_text(json.dumps({"snapshot_id": "20261010T090000Z", "devices": {"R1": {
            "name": "R1", "os": "iosxe", "connected": True,
            "commands": [{"command": "show version", "status": "parsed"}],
            "vrfs_not_read": {"CUST/B": refused, "BLUE": over, "GREEN": over},
        }}}), encoding="utf-8")
        gaps = Snapshot.load(root).gaps()
        self.assertIn(f"R1: the per-VRF tables of 2 VRF(s) not read — {over}", gaps)
        self.assertIn(f"R1: the per-VRF tables of 1 VRF(s) not read — {refused}", gaps)
        self.assertFalse([gap for gap in gaps if "CUST/B" in gap or "BLUE" in gap])


class TestGapReporting(unittest.TestCase):
    """A gap list nobody can read is a gap list nobody reads."""

    def snapshot(self, devices):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "manifest.json").write_text(
            json.dumps(
                {
                    "disconet_version": "0.1.0",
                    "snapshot_id": "20260805T090000Z",
                    "created_at": "2026-08-05T09:00:00+00:00",
                    "devices": devices,
                }
            ),
            encoding="utf-8",
        )
        return Snapshot.load(root)

    @staticmethod
    def device(name, commands, connected=True, error=None):
        return {
            name: {
                "name": name,
                "os": "iosxr",
                "connected": connected,
                "error": error,
                "commands": [
                    {
                        "command": command,
                        "status": status,
                        "state_file": None,
                        "raw_file": None,
                        "redacted_lines": 0,
                        "seconds": 1.0,
                        "detail": detail,
                    }
                    for command, status, detail in commands
                ],
            }
        }

    def test_a_command_the_platform_lacks_is_reported_once_for_the_fleet(self):
        devices = {}
        for name in ("XR1", "XR2", "XR3"):
            devices.update(
                self.device(
                    name,
                    [
                        ("show version", "parsed", None),
                        ("show inventory", "unsupported", "invalid input"),
                    ],
                )
            )
        gaps = self.snapshot(devices).gaps()

        self.assertEqual(
            gaps, ["show inventory: not supported on 3 device(s) (XR1, XR2, XR3)"]
        )

    def test_a_ptp_router_that_rejects_one_spelling_is_not_called_outside_ptp(self):
        """BUG-023: the two foreign-masters spellings are one command.

        Every XR router is sent both, and one is always rejected. A router
        whose other PTP commands answered is in the PTP domain, so neither the
        rejected spelling nor 'do not participate in PTP' belongs in the gaps.
        """
        devices = {}
        devices.update(
            self.device(
                "XR1",
                [
                    ("show version", "parsed", None),
                    ("show ptp platform servo", "unparsed", "ParserNotFound"),
                    ("show ptp foreign masters", "unparsed", "ParserNotFound"),
                    ("show ptp foreign-masters", "unsupported", "invalid input"),
                ],
            )
        )
        devices.update(
            self.device(
                "XR2",
                [
                    ("show version", "parsed", None),
                    ("show ptp platform servo", "unsupported", "invalid input"),
                    ("show ptp foreign masters", "unsupported", "invalid input"),
                    ("show ptp foreign-masters", "unsupported", "invalid input"),
                ],
            )
        )
        gaps = self.snapshot(devices).gaps()

        self.assertFalse([gap for gap in gaps if "XR1" in gap], gaps)
        self.assertTrue(gaps, gaps)
        for gap in gaps:
            self.assertIn("(XR2)", gap)
            self.assertIn("do not participate in PTP", gap)

    def test_the_xr_multicast_tables_read_from_text_are_no_gap(self):
        """BUG-187: Genie has no parser for these, and the multicast readers read their text.

        Every XR router reported both as unparsed gaps in the document, about
        tables the multicast section is built from.
        """
        devices = self.device(
            "XR1",
            [
                ("show version", "parsed", None),
                ("show pim neighbor", "unparsed", "ParserNotFound"),
                ("show mrib route", "unparsed", "ParserNotFound"),
            ],
        )
        self.assertEqual(self.snapshot(devices).gaps(), [])

    def test_a_ptp_command_missing_on_a_ptp_router_is_an_ordinary_gap(self):
        """BUG-023: a PTP router that lacks one command lacks that command, nothing more."""
        devices = self.device(
            "XR1",
            [
                ("show ptp platform servo", "unparsed", "ParserNotFound"),
                ("show ptp advertised-clock", "unsupported", "invalid input"),
            ],
        )
        gaps = self.snapshot(devices).gaps()

        self.assertEqual(
            gaps, ["show ptp advertised-clock: not supported on 1 device(s) (XR1)"]
        )

    def test_a_device_that_connects_and_answers_nothing_is_not_collected(self):
        # The session opened and then lost its state machine: `connected` is
        # true and not one command came back. Calling that collected puts a
        # false device count in the document.
        devices = self.device(
            "CSR2",
            [
                (command, "failed", 'StateMachineError: Failed while bringing device to "any" state')
                for command in ("show version", "show ip arp", "show ip interface")
            ],
        )
        snapshot = self.snapshot(devices)

        self.assertFalse(snapshot.produced_data("CSR2"))
        self.assertEqual(snapshot.device_names, [])
        gaps = snapshot.gaps()
        self.assertEqual(len(gaps), 1, gaps)
        self.assertIn("connected but answered nothing", gaps[0])
        self.assertIn("StateMachineError", gaps[0])

    def test_one_usable_command_is_enough_to_count_as_collected(self):
        devices = self.device(
            "XR1",
            [("show version", "parsed", None), ("show inventory", "unsupported", "invalid input")],
        )
        snapshot = self.snapshot(devices)

        self.assertTrue(snapshot.produced_data("XR1"))
        self.assertEqual(snapshot.device_names, ["XR1"])

    def test_real_failures_stay_per_device(self):
        devices = {}
        devices.update(
            self.device(
                "XR1",
                [("show ip arp", "parsed", None),
                 ("show version", "failed", "no prompt within 120s")],
            )
        )
        devices.update(
            self.device(
                "XR2",
                [("show ip arp", "parsed", None),
                 ("show version", "unparsed", "ParserNotFound")],
            )
        )
        devices.update(self.device("XR3", [], connected=False, error="ConnectionError"))
        gaps = self.snapshot(devices).gaps()

        self.assertEqual(len(gaps), 3)
        self.assertTrue(any(gap.startswith("XR1: show version failed") for gap in gaps))
        self.assertTrue(any(gap.startswith("XR2: show version unparsed") for gap in gaps))
        self.assertTrue(any("XR3: not reached" in gap for gap in gaps))


class TestTwoVrfsThatDifferOnlyInCase(unittest.TestCase):
    """BUG-253: `vrf Mgmt` and `vrf MGMT` are two VRFs, and each table is read as its own."""

    def snapshot(self, root):
        commands = []
        for command, stem in (
            ("show version", "show_version"),
            ("show ip arp vrf Mgmt", "show_ip_arp_vrf_mgmt"),
            ("show ip arp vrf MGMT", "show_ip_arp_vrf_mgmt_2"),
        ):
            for kind, suffix, body in (("state", "json", json.dumps({"read": command})), ("raw", "txt", f"{command}\n")):
                path = root / "R1" / kind / f"{stem}.{suffix}"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            commands.append({
                "command": command, "status": "parsed",
                "state_file": f"R1/state/{stem}.json", "raw_file": f"R1/raw/{stem}.txt",
            })
        (root / "manifest.json").write_text(json.dumps({
            "snapshot_id": "20261010T090000Z",
            "devices": {"R1": {"name": "R1", "os": "iosxe", "connected": True, "commands": commands}},
        }), encoding="utf-8")
        return Snapshot.load(root)

    def test_each_vrfs_table_reads_its_own_state_and_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self.snapshot(Path(tmp))
            for command in snapshot.commands("R1"):
                self.assertEqual(snapshot.state("R1", command), {"read": command})
                self.assertEqual(snapshot.raw("R1", command).strip(), command)

    def test_a_command_spelt_another_way_is_still_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self.snapshot(Path(tmp))
            self.assertEqual(snapshot.state("R1", "Show  Version"), {"read": "show version"})


class TestRawOnly(CollectCommandTestCase):
    RUNNING_CONFIG = (
        "hostname R1\n"
        "enable secret 5 $1$abcd$KJhgFDsaQwErTy123\n"
        "interface GigabitEthernet1\n"
        " ip address 10.0.0.1 255.255.255.252\n"
    )

    def test_running_config_is_never_parsed(self):
        device = FakeDevice(raw={"show running-config": self.RUNNING_CONFIG})
        result = self.collect(device, command="show running-config", parse=False)

        self.assertEqual(result.status, "raw")
        self.assertEqual(device.parsed_from_output, [], "raw_only must not be parsed")
        self.assertIsNone(result.state_file)

    def test_secrets_are_redacted_before_reaching_disk(self):
        device = FakeDevice(raw={"show running-config": self.RUNNING_CONFIG})
        result = self.collect(device, command="show running-config", parse=False)

        written = self.read(result.raw_file)
        self.assertNotIn("$1$abcd$KJhgFDsaQwErTy123", written)
        self.assertIn("ip address 10.0.0.1 255.255.255.252", written)
        self.assertEqual(result.redacted_lines, 1)


class TestReadOnlyGateDuringCollection(CollectCommandTestCase):
    def test_command_outside_the_allowlist_never_reaches_the_device(self):
        device = FakeDevice()
        with self.assertRaises(CommandNotAllowed):
            self.collect(device, command="show clock")
        self.assertEqual(device.executed, [], "no command may reach the device")

    def test_configuration_command_never_reaches_the_device(self):
        device = FakeDevice()
        with self.assertRaises(CommandNotAllowed):
            self.collect(device, command="configure terminal")
        self.assertEqual(device.executed, [])


class RunCollectTestCase(OwnTempDirectoryTestCase):
    """A whole `run_collect` over three testbed devices, pyATS stood in for."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name) / "snapshots"
        self.testbed_path = Path(tmp.name) / "testbed.yaml"
        self.testbed_path.write_text("devices: {}\n", encoding="utf-8")
        devices = {
            name: SimpleNamespace(name=name, os="iosxe", connections={}, custom={}, credentials={})
            for name in ("R1", "R2", "R3")
        }
        self.testbed = SimpleNamespace(devices=devices)
        genie = types.ModuleType("genie")
        genie_testbed = types.ModuleType("genie.testbed")
        genie_testbed.load = lambda path: self.testbed
        modules = mock.patch.dict(sys.modules, {"genie": genie, "genie.testbed": genie_testbed})
        modules.start()
        self.addCleanup(modules.stop)

    @staticmethod
    def answered(name):
        result = collector.DeviceResult(name=name, os="iosxe", connected=True)
        result.commands.append(collector.CommandResult(command="show version", status="parsed"))
        return result


class TestAnInterruptedRunKeepsWhatItCollected(RunCollectTestCase):
    """BUG-114: Ctrl-C, a hang-up or a defect halfway through no longer loses the whole run.

    The manifest was written only at the end, so every device already
    collected sat in a directory nothing could read.
    """

    def run_until(self, interruption):
        def collect_device(device, *args, **kwargs):
            if device.name == "R1":
                return self.answered("R1")
            raise interruption
        with mock.patch.object(collector, "_collect_device", side_effect=collect_device), \
                mock.patch.object(collector, "record_snapshot") as recorded:
            with self.assertRaises(type(interruption)):
                collector.run_collect(self.testbed_path, base_dir=self.base, workers=1)
        [root] = list(self.base.iterdir())
        return root, recorded

    def test_ctrl_c_leaves_a_manifest_of_the_devices_that_finished(self):
        root, recorded = self.run_until(KeyboardInterrupt())
        snapshot = Snapshot.load(root)
        self.assertEqual(sorted(snapshot.devices), ["R1"])
        self.assertEqual(snapshot.manifest["interrupted"]["not_collected"], ["R2", "R3"])
        gaps = snapshot.gaps()
        self.assertTrue(any("interrupted" in gap and "R2, R3" in gap for gap in gaps), gaps)
        # A run cut short is not folded into the estate database on its own.
        recorded.assert_not_called()

    def test_a_defect_that_escapes_leaves_one_too(self):
        root, _ = self.run_until(RuntimeError("worker failed"))
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(manifest["devices"]), ["R1"])
        self.assertIn("worker failed", manifest["interrupted"]["reason"])

    def run_interrupted_while_r3_is_in_session(self, interrupts: int):
        """Ctrl-C (R2's turn) while R3 is in a session, then `interrupts` more while the pool drains.

        The real wait runs once the interrupts are spent, after R3 is let go
        when the run is still waiting for it.
        """
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def collect_device(device, *args, **kwargs):
            if device.name == "R2":
                raise KeyboardInterrupt
            if device.name == "R3":
                started.set()
                release.wait(10)
            return self.answered(device.name)

        real_wait = collector.wait
        pending = [interrupts]

        def wait(futures, *args, **kwargs):
            started.wait(10)
            if pending[0]:
                pending[0] -= 1
                raise KeyboardInterrupt
            release.set()
            return real_wait(futures, *args, **kwargs)

        with mock.patch.object(collector, "_collect_device", side_effect=collect_device), \
                mock.patch.object(collector, "wait", side_effect=wait), \
                mock.patch.object(collector, "record_snapshot"):
            with self.assertRaises(KeyboardInterrupt):
                collector.run_collect(self.testbed_path, base_dir=self.base, workers=3)
        [root] = list(self.base.iterdir())
        return Snapshot.load(root)

    def test_a_second_ctrl_c_while_the_devices_in_session_finish_waits_for_them_again(self):
        """F-38: the second interrupt escaped the wait, and the manifest was written while R3 was still collected.

        R3 finished after the manifest was written, which did not list it as
        collected: its answers were on disk and in no device table.
        """
        snapshot = self.run_interrupted_while_r3_is_in_session(interrupts=1)

        self.assertEqual(sorted(snapshot.devices), ["R1", "R3"])
        self.assertEqual(snapshot.manifest["interrupted"]["not_collected"], ["R2"])
        self.assertNotIn("in_session", snapshot.manifest["interrupted"])

    def test_a_third_ctrl_c_stops_waiting_and_the_manifest_names_the_device_still_in_session(self):
        snapshot = self.run_interrupted_while_r3_is_in_session(interrupts=2)

        self.assertEqual(sorted(snapshot.devices), ["R1"])
        self.assertEqual(snapshot.manifest["interrupted"]["not_collected"], ["R2", "R3"])
        self.assertEqual(snapshot.manifest["interrupted"]["in_session"], ["R3"])
        gaps = snapshot.gaps()
        self.assertTrue(any(gap.startswith("R2: not collected") for gap in gaps), gaps)
        self.assertTrue(any(gap.startswith("R3: still in session") for gap in gaps), gaps)

    @unittest.skipUnless(hasattr(signal, "SIGHUP"), "no SIGHUP on this platform")
    def test_a_hang_up_ends_the_run_the_way_ctrl_c_does(self):
        before = signal.getsignal(signal.SIGHUP)
        with self.assertRaises(KeyboardInterrupt):
            with collector._hangup_as_interrupt():
                signal.raise_signal(signal.SIGHUP)
        self.assertIs(signal.getsignal(signal.SIGHUP), before)


class TestARunOfNamedDevicesSaysWhatItLeftOut(RunCollectTestCase):
    """`collect --devices R2` wrote a manifest like a whole run's, so the run read by default was that one device.

    Its `requested_devices` was R2, and nothing said whether the testbed had
    more: the run read without --snapshot, a retry's among them, took it
    for the estate.
    """

    def run_over(self, devices=None) -> dict:
        def collect_device(device, *args, **kwargs):
            return self.answered(device.name)
        with mock.patch.object(collector, "_collect_device", side_effect=collect_device), \
                mock.patch.object(collector, "record_snapshot"):
            return collector.run_collect(self.testbed_path, base_dir=self.base, devices=devices, workers=1)

    def test_the_testbed_devices_not_named_are_recorded(self):
        self.assertEqual(self.run_over(["R2"])["devices_not_requested"], ["R1", "R3"])

    def test_a_run_of_the_whole_testbed_left_nothing_out(self):
        self.assertEqual(self.run_over()["devices_not_requested"], [])

    def test_naming_every_device_is_a_run_of_the_whole_testbed(self):
        self.assertEqual(self.run_over(["R3", "R1", "R2"])["devices_not_requested"], [])

    def test_a_run_cut_short_says_it_too(self):
        def collect_device(device, *args, **kwargs):
            if device.name == "R1":
                return self.answered("R1")
            raise KeyboardInterrupt
        with mock.patch.object(collector, "_collect_device", side_effect=collect_device), \
                mock.patch.object(collector, "record_snapshot"):
            with self.assertRaises(KeyboardInterrupt):
                collector.run_collect(self.testbed_path, base_dir=self.base, devices=["R1", "R2"], workers=1)
        [root] = list(self.base.iterdir())
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["devices_not_requested"], ["R3"])


class TestARunNeverWritesIntoAnotherRunsDirectory(RunCollectTestCase):
    """C-08: a snapshot is named for the second it started, and a merge in that second had the name already.

    The collect wrote its devices and its manifest into the merge's
    directory, over the merge's own.
    """

    def test_a_run_that_starts_in_the_same_second_as_a_merge_takes_the_next_name(self):
        taken = self.base / "20261014T120000Z"
        taken.mkdir(parents=True)
        (taken / "manifest.json").write_text('{"merged_from": ["a", "b"]}', encoding="utf-8")
        (self.base / "20261014T120000Z-2").mkdir()

        def collect_device(device, *args, **kwargs):
            return self.answered(device.name)
        with mock.patch.object(collector, "snapshot_dir", return_value=taken), \
                mock.patch.object(collector, "_collect_device", side_effect=collect_device), \
                mock.patch.object(collector, "record_snapshot"):
            manifest = collector.run_collect(self.testbed_path, base_dir=self.base, workers=1)

        self.assertEqual(manifest["snapshot_id"], "20261014T120000Z-3")
        self.assertTrue((self.base / "20261014T120000Z-3" / "manifest.json").is_file())
        self.assertEqual(json.loads((taken / "manifest.json").read_text(encoding="utf-8")), {"merged_from": ["a", "b"]})
        self.assertEqual(sorted(path.name for path in taken.iterdir()), ["manifest.json"])


class TestAFenceThatCannotBeUsedStopsTheRunBeforeItStarts(RunCollectTestCase):
    """BUG-331: the crawl fence was read after the snapshot directory and its log existed.

    A malformed one escaped as a ValueError, and either error left an empty
    snapshot directory behind and the run's log handler attached.
    """

    def test_a_malformed_or_missing_fence_is_a_collection_error_that_leaves_nothing(self):
        disconet_log = logging.getLogger("disconet")
        before = list(disconet_log.handlers)
        for scope in (["10.0.0.0/33"], ["10.0.0.0/8", "sw-1"], []):
            with self.subTest(scope=scope):
                with self.assertRaises(collector.CollectionError) as raised:
                    collector.run_collect(
                        self.testbed_path, base_dir=self.base, workers=1, crawl=True, crawl_scope=scope,
                    )
                self.assertIn("fence", str(raised.exception))
                self.assertFalse(self.base.exists() and any(self.base.iterdir()))
                self.assertEqual(disconet_log.handlers, before)

    def test_an_error_before_the_first_device_still_detaches_the_run_log(self):
        disconet_log = logging.getLogger("disconet")
        before = list(disconet_log.handlers)
        with mock.patch.object(collector, "_credential_sets_of", side_effect=RuntimeError("unreadable")):
            with self.assertRaises(RuntimeError):
                collector.run_collect(self.testbed_path, base_dir=self.base, workers=1)
        self.assertEqual(disconet_log.handlers, before)


class TestTheSessionLogIsTheRedactedTranscripts(RunCollectTestCase):
    """BUG-188: session.log is every device's connect.log, joined after the run.

    It was written by a handler on the 'unicon' logger, whose connection
    loggers do not pass their records up, so the file stayed empty; and a
    record at a time defeats the redaction, which a whole transcript does not.
    """

    def collect_device(self, device, policy, snapshot_root, *args, **kwargs):
        unicon = logging.getLogger("unicon")
        self.during.append((unicon.level, list(unicon.handlers)))
        transcript = snapshot_root / device.name / collector.CONNECT_LOG_NAME
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text(
            f"{device.name}#show version\nsnmp {{\n    community {REDACTION_MARKER};\n}}\n", encoding="utf-8",
        )
        result = self.answered(device.name)
        result.connect_log = f"{device.name}/{collector.CONNECT_LOG_NAME}"
        return result

    def test_every_devices_dialog_is_in_the_session_log(self):
        self.during: list = []
        unicon = logging.getLogger("unicon")
        before = (unicon.level, list(unicon.handlers))
        with mock.patch.object(collector, "_collect_device", side_effect=self.collect_device), \
                mock.patch.object(collector, "record_snapshot"):
            manifest = collector.run_collect(self.testbed_path, base_dir=self.base, workers=1, session_log=True)
        session = (self.base / manifest["snapshot_id"] / collector.SESSION_LOG_NAME).read_text(encoding="utf-8")
        for name in ("R1", "R2", "R3"):
            self.assertIn(f"{name}#show version", session)
        self.assertEqual(session.count(REDACTION_MARKER), 3)
        # BUG-056: unicon's level is never touched, and it is given no handler.
        self.assertEqual(self.during, [before] * 3)
        self.assertEqual((unicon.level, list(unicon.handlers)), before)

    def test_a_device_with_no_transcript_is_named_as_such(self):
        results = [collector.DeviceResult(name="R3")]
        root = self.base / "20261010T120000Z"
        root.mkdir(parents=True)
        collector.write_session_log(root, results)
        self.assertIn("R3: no session transcript", (root / collector.SESSION_LOG_NAME).read_text(encoding="utf-8"))


class UniconFileHandler(logging.FileHandler):
    """unicon's transcript as it writes one: its own messages a stamped line
    each, and the device's words raw, in whatever chunks the session read them."""

    terminator = ""
    STAMP = logging.Formatter("%(asctime)s: %%UNICON-%(levelname)s: %(message)s\n")

    def format(self, record):
        return record.getMessage() if getattr(record, "spawn", False) else self.STAMP.format(record)


class UniconTranscriptDevice:
    """A device whose login writes its dialog the way unicon does.

    Through a connection logger of its own, `unicon.R1.1`, which passes
    nothing up to `unicon`; the device's words chunk by chunk, so a secret
    can sit in two writes and a Junos block in several.
    """

    CHUNKS = (
        "admin@192.0.2.1's password: Hop!Pa",
        "ss77\nR1#",
        "show running-config\nsnmp-server comm",
        "unity s3cr3t RO\nsnmp {\n",
        "    community s3cr3t-j {\n        authorization read-only;\n    }\n}\nR1#",
    )

    def __init__(self, name="R1"):
        self.name = name
        self.os = "iosxe"
        self.connections: dict = {}
        self.custom: dict = {}
        self.credentials = {"default": {"username": "admin", "password": "Hop!Pass77"}}
        self.default = SimpleNamespace(settings=SimpleNamespace(EXEC_TIMEOUT=60))
        self.logger = logging.getLogger(f"unicon.{name}.1")
        self.handler: logging.Handler | None = None

    def connect(self, **kwargs):
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)
        self.handler = UniconFileHandler(kwargs["logfile"], encoding="utf-8")
        self.logger.addHandler(self.handler)
        self.logger.info("+++ %s logfile %s +++", self.name, kwargs["logfile"])
        for chunk in self.CHUNKS:
            self.logger.info("%s", chunk, extra={"spawn": True})

    def disconnect(self):
        if self.handler is not None:
            self.logger.removeHandler(self.handler)
            self.handler.close()
            self.handler = None

    def execute(self, command, timeout=None):
        return f"{self.name}: {command}"

    def parse(self, command, output=None):
        return {"answered": command}


class TestTheSessionLogIsRedactedAsUniconWritesIt(RunCollectTestCase):
    """BUG-189: no session-log test saw a transcript the way unicon writes one.

    The run-level test stood in for the collection with a connect.log
    already redacted, and the others logged whole lines to a logger of their
    own; none had unicon's connection logger, which passes nothing up, or the
    device's words in the chunks they arrived in. Here the collection is the
    real one and only the device is a stand-in.
    """

    def setUp(self):
        super().setUp()
        self.device = UniconTranscriptDevice()
        self.addCleanup(self.device.disconnect)
        self.addCleanup(setattr, self.device.logger, "propagate", True)
        self.testbed.devices = {"R1": self.device}
        with mock.patch.object(collector, "record_snapshot"):
            manifest = collector.run_collect(self.testbed_path, base_dir=self.base, workers=1, session_log=True)
        self.root = self.base / manifest["snapshot_id"]
        self.session = (self.root / collector.SESSION_LOG_NAME).read_text(encoding="utf-8")

    def test_no_secret_reaches_the_session_log_whichever_writes_it_was_split_across(self):
        for secret in ("Hop!Pass77", "Hop!Pa", "s3cr3t"):
            self.assertNotIn(secret, self.session)
        self.assertEqual(self.session.count(REDACTION_MARKER), 3)

    def test_the_dialog_itself_is_there_though_unicons_logger_passes_nothing_up(self):
        self.assertIn("%UNICON-INFO: +++ R1 logfile", self.session)
        self.assertIn("R1#show running-config", self.session)
        self.assertIn("authorization read-only;", self.session)

    def test_the_clear_transcript_is_gone_once_the_run_is_over(self):
        self.assertFalse((self.root / "R1" / collector.CONNECT_LOG_TEMP).exists())


class TestOneDeviceNeverStopsTheRun(OwnTempDirectoryTestCase):
    """BUG-114: an error that escapes one device is that device's error, and its answers are kept."""

    def test_what_the_device_answered_before_the_error_is_kept(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        policy = CommandPolicy({"iosxe": {"parse": ["show version"], "probe": ["ping {addr}"]}})
        with mock.patch.object(collector, "_probe_device", side_effect=RuntimeError("probe defect")):
            outcome = collector._collect_device(RecordingDevice(), policy, Path(tmp.name), verify_reachability=True)
        self.assertTrue(outcome.connected)
        self.assertEqual([command.status for command in outcome.commands], ["parsed"])
        self.assertIn("probe defect", outcome.error)

    def test_the_commands_the_error_left_unsent_are_recorded_as_not_sent(self):
        """F-37: a device that crashed after its login left no result for the commands after the crash.

        The gap list then named only what came back badly, as if the rest
        of the plan had been asked and answered.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        policy = CommandPolicy({"iosxe": {
            "parse": ["show version", "show inventory"], "raw_only": ["show running-config"],
        }})
        real = collector._collect_command

        def crash_on_inventory(device, os_name, command, *args, **kwargs):
            if command == "show inventory":
                raise TypeError("reader defect")
            return real(device, os_name, command, *args, **kwargs)

        with mock.patch.object(collector, "_collect_command", side_effect=crash_on_inventory):
            outcome = collector._collect_device(RecordingDevice(), policy, Path(tmp.name))
        self.assertTrue(outcome.connected)
        self.assertIn("reader defect", outcome.error)
        self.assertEqual(
            [(command.command, command.status) for command in outcome.commands],
            [("show version", "parsed"), ("show inventory", "failed"), ("show running-config", "failed")],
        )
        self.assertEqual(
            {command.detail for command in outcome.commands[1:]}, {collector.NOT_SENT_AFTER_ERROR_DETAIL},
        )

    def test_the_gap_list_names_the_error_of_a_device_that_crashed_after_its_login(self):
        """F-37: a device `connected` with an `error` had its error in no gap line."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "20240101T000000Z"
        (root / "r1" / "raw").mkdir(parents=True)
        (root / "r1" / "raw" / "show_version.txt").write_text("Cisco IOS XE Software\n", encoding="utf-8")
        error = "collection stopped by an unexpected error: TypeError: boom"
        devices = {"r1": {
            "name": "r1", "os": "iosxe", "connected": True, "error": error,
            "commands": [{"command": "show version", "status": "unparsed", "raw_file": "r1/raw/show_version.txt"}],
        }}
        (root / "manifest.json").write_text(json.dumps({
            "snapshot_id": root.name, "created_at": "2024-01-01T00:00:00+00:00", "devices": devices,
            "summary": collector.summarise_devices(devices), "features": [],
        }), encoding="utf-8")

        gaps = Snapshot.load(root).gaps()
        self.assertIn(f"r1: {error}", gaps)
        self.assertIn("r1: show version unparsed", gaps)


class TestTheJsonFilesAreWrittenWhole(unittest.TestCase):
    """BUG-114: a write cut off halfway leaves the previous file, never half of the new one."""

    def test_a_failed_write_leaves_the_old_file(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "manifest.json"
        collector._write_json(path, {"devices": {"R1": {}}})

        def half(payload, handle, **kwargs):
            handle.write('{"devices": ')
            raise OSError("No space left on device")

        with mock.patch.object(collector.json, "dump", side_effect=half):
            with self.assertRaises(OSError):
                collector._write_json(path, {"devices": {}})
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"devices": {"R1": {}}})


if __name__ == "__main__":
    unittest.main()
