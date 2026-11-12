"""The collection window and the allowlist hash, recorded by the run that knows them.

An export states when the snapshot was collected, from its start to its end,
and which allowlist the run was held to. Neither can be worked out afterwards:
the newest file in a snapshot is no measure of when the run ended, and the
allowlist on disk may have been edited since. So the run writes both into its
manifest, `finished_at` beside `created_at` and `commands_sha256` beside
`commands_file`, and these tests hold it to that: the hash is of the very
bytes that were parsed, the finish comes after every device, a run cut short
records its end too, the committed demo carries both, and the synth writer
that wrote the demo ends it when its last device answered.

Public scope: the device names are the demo's and no address appears.
"""

from __future__ import annotations

import hashlib
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
from netstate.collector import DEFAULT_COMMANDS_FILE, CollectionError, CommandPolicy, _build_manifest
from tests.test_collector_enable import OwnTempDirectoryTestCase

ROOT = Path(__file__).resolve().parents[1]

# An allowlist of the shape commands.yaml has, with a comment and a blank
# line: the hash is of the file as written, not of what the YAML says.
ALLOWLIST = (
    "# A test allowlist, read by nothing else.\n"
    "iosxe:\n"
    "  parse:\n"
    "    - show version\n"
    "\n"
    "  raw_only:\n"
    "    - show running-config\n"
)
EDITED = "iosxe:\n  parse:\n    - show inventory\n"

NAMES = ("rbt-ald-pe1", "rbt-bht-p2", "rbt-ald-p1")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AllowlistTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "commands.yaml"
        # Bytes, so the line endings are the ones written here on any platform.
        self.path.write_bytes(ALLOWLIST.encode("utf-8"))


class TheAllowlistIsHashedFromTheBytesItWasParsedFrom(AllowlistTestCase):
    def test_the_hash_is_of_the_exact_bytes_of_the_file(self):
        policy = CommandPolicy.load(self.path)
        self.assertEqual(policy.sha256, hashlib.sha256(ALLOWLIST.encode("utf-8")).hexdigest())
        self.assertEqual(policy.sha256, sha256_of(self.path))

    def test_the_hash_is_lowercase_hex_of_sha256(self):
        self.assertRegex(CommandPolicy.load(self.path).sha256, r"\A[0-9a-f]{64}\Z")

    def test_a_change_that_leaves_the_commands_alone_still_changes_the_hash(self):
        # A comment says nothing to the parser and is still part of the file
        # the run was held to; carriage returns are bytes too.
        before = CommandPolicy.load(self.path)
        self.path.write_bytes(ALLOWLIST.replace("\n", "\r\n").encode("utf-8"))
        after = CommandPolicy.load(self.path)
        self.assertEqual(after.allowed_commands("iosxe"), before.allowed_commands("iosxe"))
        self.assertNotEqual(after.sha256, before.sha256)
        self.assertEqual(after.sha256, sha256_of(self.path))

    def test_the_file_is_read_once_so_an_edit_after_the_read_reaches_neither_the_hash_nor_the_plan(self):
        # Hashed from one read and parsed from another, the hash could name a
        # file the run was never held to. The file is edited the moment it has
        # been read; a second read for either purpose would see the edit.
        real = Path.read_bytes
        reads: list[Path] = []

        def read_then_edit(path: Path) -> bytes:
            data = real(path)
            reads.append(path)
            path.write_bytes(EDITED.encode("utf-8"))
            return data

        with mock.patch.object(Path, "read_bytes", autospec=True, side_effect=read_then_edit):
            policy = CommandPolicy.load(self.path)
        self.assertEqual(reads, [self.path])
        self.assertEqual(policy.sha256, hashlib.sha256(ALLOWLIST.encode("utf-8")).hexdigest())
        self.assertEqual(policy.allowed_commands("iosxe"), {"show version", "show running-config"})
        self.assertNotEqual(sha256_of(self.path), policy.sha256)

    def test_nothing_but_the_one_read_reaches_the_file(self):
        # The file is never written: any other read, for the hash or for the
        # parse, would find nothing there and fail.
        absent = self.dir / "never-written.yaml"
        data = ALLOWLIST.encode("utf-8")
        with mock.patch.object(Path, "is_file", autospec=True, return_value=True), \
                mock.patch.object(Path, "read_bytes", autospec=True, return_value=data) as read:
            policy = CommandPolicy.load(absent)
        read.assert_called_once_with(absent)
        self.assertFalse(absent.exists())
        self.assertEqual(policy.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(policy.allowed_commands("iosxe"), {"show version", "show running-config"})

    def test_the_installed_allowlist_is_hashed_too(self):
        self.assertEqual(CommandPolicy.load().sha256, sha256_of(Path(DEFAULT_COMMANDS_FILE)))

    def test_a_policy_built_in_memory_has_no_hash(self):
        # It was read from no file, and a hash of some file would claim it was.
        self.assertIsNone(CommandPolicy({"iosxe": {"parse": ["show version"]}}).sha256)

    def test_an_allowlist_that_is_not_utf8_is_still_refused_before_any_connection(self):
        self.path.write_bytes(b"iosxe:\n  parse:\n    - show version \xff\n")
        with self.assertRaisesRegex(CollectionError, "not readable YAML"):
            CommandPolicy.load(self.path)


class TheManifestRecordsTheWindowAndTheHash(AllowlistTestCase):
    STARTED = datetime(2026, 10, 26, 9, 14, 5, tzinfo=timezone.utc)

    def build(self, policy: CommandPolicy, **kwargs):
        return _build_manifest(
            self.dir / "20261026T091405Z", self.STARTED, "testbed.yaml", policy, list(NAMES), [], 90, 120, **kwargs,
        )

    def test_the_allowlist_hash_the_run_loaded_is_recorded(self):
        policy = CommandPolicy.load(self.path)
        manifest = self.build(policy)
        self.assertEqual(manifest["commands_sha256"], policy.sha256)
        self.assertEqual(manifest["commands_sha256"], sha256_of(self.path))
        self.assertEqual(manifest["commands_file"], str(self.path))

    def test_a_policy_built_in_memory_records_no_hash(self):
        manifest = self.build(CommandPolicy({"iosxe": {"parse": ["show version"]}}))
        self.assertIsNone(manifest["commands_sha256"])

    def test_the_finish_is_recorded_in_utc_in_the_form_of_the_start(self):
        # Handed over in another zone, it is written in UTC all the same, so
        # the two ends of the window are read the same way.
        finished = datetime(2026, 10, 26, 11, 16, 15, tzinfo=timezone(timedelta(hours=2)))
        manifest = self.build(CommandPolicy.load(self.path), finished_at=finished)
        self.assertEqual(manifest["created_at"], "2026-10-26T09:14:05+00:00")
        self.assertEqual(manifest["finished_at"], "2026-10-26T09:16:15+00:00")
        self.assertEqual(datetime.fromisoformat(manifest["finished_at"]), finished)

    def test_a_manifest_of_a_run_still_under_way_has_no_finish(self):
        # The crawl reads one between its waves; nothing has ended yet.
        self.assertIsNone(self.build(CommandPolicy.load(self.path))["finished_at"])

    def test_both_survive_the_manifest_file(self):
        policy = CommandPolicy.load(self.path)
        manifest = self.build(policy, finished_at=self.STARTED + timedelta(minutes=2))
        target = self.dir / "manifest.json"
        collector._write_json(target, manifest)
        written = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(written["commands_sha256"], policy.sha256)
        self.assertEqual(written["finished_at"], "2026-10-26T09:16:05+00:00")


class RunCollectTestCase(OwnTempDirectoryTestCase):
    """A whole `run_collect` over three of the demo's devices, pyATS stood in for."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name) / "snapshots"
        self.testbed_path = Path(tmp.name) / "testbed.yaml"
        self.testbed_path.write_text("devices: {}\n", encoding="utf-8")
        self.commands = Path(tmp.name) / "commands.yaml"
        self.commands.write_bytes(ALLOWLIST.encode("utf-8"))
        devices = {
            name: SimpleNamespace(name=name, os="iosxe", connections={}, custom={}, credentials={})
            for name in NAMES
        }
        self.testbed = SimpleNamespace(devices=devices)
        genie = types.ModuleType("genie")
        genie_testbed = types.ModuleType("genie.testbed")
        genie_testbed.load = lambda path: self.testbed
        modules = mock.patch.dict(sys.modules, {"genie": genie, "genie.testbed": genie_testbed})
        modules.start()
        self.addCleanup(modules.stop)
        # When each stand-in device finished, by the wall clock.
        self.done: dict[str, datetime] = {}

    def answered(self, name: str) -> collector.DeviceResult:
        result = collector.DeviceResult(name=name, os="iosxe", connected=True)
        result.commands.append(collector.CommandResult(command="show version", status="parsed"))
        self.done[name] = datetime.now(timezone.utc)
        return result

    def collect(self, side_effect, **kwargs):
        with mock.patch.object(collector, "_collect_device", side_effect=side_effect), \
                mock.patch.object(collector, "record_snapshot"):
            return collector.run_collect(
                self.testbed_path, base_dir=self.base, commands_file=self.commands, workers=1, **kwargs,
            )

    def written(self) -> dict:
        [root] = list(self.base.iterdir())
        return json.loads((root / "manifest.json").read_text(encoding="utf-8"))


class ARunRecordsWhenItEndedAndWhichAllowlistItUsed(RunCollectTestCase):
    def test_the_finish_follows_the_start_and_every_device(self):
        manifest = self.collect(lambda device, *args, **kwargs: self.answered(device.name))
        started = datetime.fromisoformat(manifest["created_at"])
        finished = datetime.fromisoformat(manifest["finished_at"])
        self.assertEqual(finished.utcoffset(), timedelta(0))
        self.assertGreaterEqual(finished, started)
        self.assertEqual(sorted(self.done), sorted(NAMES))
        self.assertGreaterEqual(finished, max(self.done.values()))
        self.assertEqual(self.written()["finished_at"], manifest["finished_at"])

    def test_the_hash_is_of_the_allowlist_the_run_loaded(self):
        manifest = self.collect(lambda device, *args, **kwargs: self.answered(device.name))
        self.assertEqual(manifest["commands_sha256"], sha256_of(self.commands))
        self.assertNotEqual(manifest["commands_sha256"], sha256_of(Path(DEFAULT_COMMANDS_FILE)))
        self.assertEqual(self.written()["commands_sha256"], sha256_of(self.commands))

    def test_a_run_cut_short_records_its_end_and_its_allowlist_too(self):
        def collect_device(device, *args, **kwargs):
            if device.name == NAMES[0]:
                return self.answered(device.name)
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.collect(collect_device)
        manifest = self.written()
        self.assertIn("interrupted", manifest)
        started = datetime.fromisoformat(manifest["created_at"])
        finished = datetime.fromisoformat(manifest["finished_at"])
        self.assertEqual(finished.utcoffset(), timedelta(0))
        self.assertGreaterEqual(finished, started)
        self.assertGreaterEqual(finished, self.done[NAMES[0]])
        self.assertEqual(manifest["commands_sha256"], sha256_of(self.commands))


if __name__ == "__main__":
    unittest.main()
