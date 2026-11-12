"""Snapshots, the estate database and traces are readable by their owner only.

Every test runs under umask 022, the common default that made estate.db
0644 and the snapshot directories 0755 before this was fixed.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from netstate import private, store
from netstate.collector import _new_snapshot_root, _write_json, _write_raw


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class Umask022(unittest.TestCase):
    def setUp(self):
        self._old = os.umask(0o022)
        self.addCleanup(os.umask, self._old)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        # The parent the tests write under is the operator's, left as it is.
        os.chmod(self.tmp, 0o755)


class TheSnapshotIsOwnerOnly(Umask022):
    def test_the_snapshot_root_and_its_base_are_0700(self):
        base = self.tmp / "estate" / "snapshots"
        root = _new_snapshot_root(base, datetime(2026, 11, 11, tzinfo=timezone.utc))
        self.assertEqual(mode(root), 0o700)
        self.assertEqual(mode(base), 0o700)
        self.assertEqual(mode(base.parent), 0o700)
        self.assertEqual(mode(self.tmp), 0o755)

    def test_a_second_run_in_the_same_second_is_0700_too(self):
        base = self.tmp / "snapshots"
        stamp = datetime(2026, 11, 11, tzinfo=timezone.utc)
        _new_snapshot_root(base, stamp)
        second = _new_snapshot_root(base, stamp)
        self.assertTrue(second.name.endswith("-2"))
        self.assertEqual(mode(second), 0o700)

    def test_an_open_snapshot_base_is_tightened_and_said(self):
        base = self.tmp / "snapshots"
        base.mkdir(mode=0o755)
        os.chmod(base, 0o755)
        with self.assertLogs("netstate.private", "WARNING") as said:
            _new_snapshot_root(base, datetime(2026, 11, 11, tzinfo=timezone.utc))
        self.assertEqual(mode(base), 0o700)
        self.assertIn("readable by other accounts", said.output[0])
        self.assertIn("chmod -R go=", said.output[0])

    def test_state_json_and_raw_output_and_their_directories(self):
        device = self.tmp / "snap" / "pe1"
        _write_json(device / "state" / "bgp.json", {"neighbours": []})
        _write_raw(device / "raw" / "show_version.txt", "Cisco IOS XR")
        for directory in (device, device / "state", device / "raw"):
            self.assertEqual(mode(directory), 0o700, directory)
        self.assertEqual(mode(device / "state" / "bgp.json"), 0o600)
        self.assertEqual(mode(device / "raw" / "show_version.txt"), 0o600)

    def test_a_json_file_rewritten_stays_0600(self):
        target = self.tmp / "manifest.json"
        _write_json(target, {"a": 1})
        _write_json(target, {"a": 2})
        self.assertEqual(mode(target), 0o600)
        self.assertFalse(target.with_name("manifest.json.tmp").exists())


class TheDatabaseIsOwnerOnly(Umask022):
    def test_a_new_database_and_its_wal_and_shm_are_0600(self):
        path = self.tmp / "snapshots" / "estate.db"
        connection = store.connect(path)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE IF NOT EXISTS probe (x)")
            connection.execute("INSERT INTO probe VALUES (1)")
            connection.commit()
            siblings = [path.with_name(path.name + s) for s in ("-wal", "-shm")]
            self.assertTrue(all(s.exists() for s in siblings))
            for candidate in (path, *siblings):
                self.assertEqual(mode(candidate), 0o600, candidate)
        finally:
            connection.close()
        self.assertEqual(mode(path.parent), 0o700)

    def test_an_existing_open_database_is_made_0600(self):
        path = self.tmp / "estate.db"
        sqlite3.connect(str(path)).close()
        os.chmod(path, 0o644)
        store.connect(path).close()
        self.assertEqual(mode(path), 0o600)
        # --db in the operator's own directory: the file is ours, the directory is not.
        self.assertEqual(mode(self.tmp), 0o755)


class TheHelpers(Umask022):
    def test_make_dir_leaves_a_directory_already_there_as_it_is(self):
        private.make_dir(self.tmp)
        self.assertEqual(mode(self.tmp), 0o755)

    def test_write_text_replaces_an_open_file_with_an_owner_only_one(self):
        target = self.tmp / "out.txt"
        target.write_text("old", encoding="utf-8")
        os.chmod(target, 0o644)
        private.write_text(target, "new")
        self.assertEqual(target.read_text(encoding="utf-8"), "new")
        self.assertEqual(mode(target), 0o600)


if __name__ == "__main__":
    unittest.main()
