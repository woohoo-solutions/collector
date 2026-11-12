"""The estate database.

The rules under test: one database holds many runs, a run ingests whole or not
at all, re-ingesting replaces rather than duplicates, unparsed output is stored
exactly as parsed state is, and a snapshot whose files are gone still reads.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from netstate import store
from netstate.collector import Snapshot


def write_snapshot(
    base: Path,
    snapshot_id: str,
    created_at: str,
    pim_status: str = "parsed",
    connected: bool = True,
) -> Path:
    root = base / snapshot_id
    (root / "R1" / "raw").mkdir(parents=True)
    (root / "R1" / "state").mkdir(parents=True)
    (root / "R1" / "raw" / "show-version.txt").write_text("Version 17.09.04a\n")
    (root / "R1" / "state" / "show-version.json").write_text(
        json.dumps({"version": {"version": "17.09.04a", "platform": "CSR1000V"}})
    )
    (root / "R1" / "raw" / "show-pim-neighbor.txt").write_text("10.0.0.2 Gi2 1d02h\n")
    manifest = {
        "snapshot_id": snapshot_id,
        "created_at": created_at,
        "testbed": "testbed.yaml",
        "disconet_version": "1.1.0",
        "mode": "loose",
        "features": ["ospf", "multicast"],
        "features_skipped": [],
        "devices": {
            "R1": {
                "name": "R1",
                "os": "iosxe",
                "platform": "CSR1000V",
                "connected": connected,
                "commands": [
                    {
                        "command": "show version",
                        "status": "parsed",
                        "raw_file": "R1/raw/show-version.txt",
                        "state_file": "R1/state/show-version.json",
                        "seconds": 1.2,
                        "redacted_lines": 0,
                    },
                    {
                        "command": "show pim neighbor",
                        "status": pim_status,
                        "raw_file": "R1/raw/show-pim-neighbor.txt",
                        "seconds": 0.4,
                        "redacted_lines": 0,
                    },
                ],
            },
            "R2": {
                "name": "R2",
                "os": "iosxr",
                "connected": False,
                "error": "connect failed: no matching key exchange method found",
                "commands": [],
            },
        },
        "summary": {"devices_total": 2, "devices_connected": 1 if connected else 0},
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    return root


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.connection = store.connect(store.default_path(self.base))

    def tearDown(self) -> None:
        self.connection.close()

    def test_the_database_lives_beside_the_snapshots_not_inside_one(self):
        # One estate, one database. A database per run would answer nothing a
        # directory per run did not already answer.
        self.assertEqual(store.default_path("snapshots"), Path("snapshots/disconet.db"))

    def test_one_run_ingests_whole(self):
        root = write_snapshot(self.base, "20260901T090000Z", "2026-09-01T09:00:00+00:00")
        rows = store.ingest(self.connection, root)
        self.assertEqual(rows, 2)
        counts = store.counts(self.connection)
        self.assertEqual(counts["snapshots"], 1)
        self.assertEqual(counts["devices"], 2)
        self.assertEqual(counts["outputs"], 2)

    def test_re_ingesting_replaces_rather_than_duplicates(self):
        root = write_snapshot(self.base, "20260901T090000Z", "2026-09-01T09:00:00+00:00")
        store.ingest(self.connection, root)
        store.ingest(self.connection, root)
        self.assertEqual(store.counts(self.connection)["outputs"], 2)

    def test_unparsed_output_is_stored_exactly_as_parsed_state_is(self):
        # The whole point of the change. An output with no Genie schema is the
        # one most likely to be wanted later, so it cannot be the one left in a
        # file while everything else moves into the database.
        root = write_snapshot(
            self.base, "20260901T090000Z", "2026-09-01T09:00:00+00:00", pim_status="unparsed"
        )
        store.ingest(self.connection, root)
        row = store.output(self.connection, "20260901T090000Z", "R1", "show pim neighbor")
        self.assertEqual(row["status"], "unparsed")
        self.assertIn("10.0.0.2", row["raw"])
        self.assertIsNone(row["state"])

    def test_the_manifest_is_kept_verbatim(self):
        # Every derived row can be rebuilt from this, so a schema mistake costs
        # a re-ingest rather than the data.
        root = write_snapshot(self.base, "20260901T090000Z", "2026-09-01T09:00:00+00:00")
        store.ingest(self.connection, root)
        recovered = store.manifest_of(self.connection, "20260901T090000Z")
        self.assertEqual(recovered, json.loads((root / "manifest.json").read_text()))

    def test_the_tool_version_is_the_engine_s_and_an_older_run_keeps_disconet_s(self):
        older = write_snapshot(self.base, "20260901T090000Z", "2026-09-01T09:00:00+00:00")
        newer = write_snapshot(self.base, "20260902T090000Z", "2026-09-02T09:00:00+00:00")
        manifest = json.loads((newer / "manifest.json").read_text())
        del manifest["disconet_version"]
        manifest["netstate_version"] = "0.1.0"
        (newer / "manifest.json").write_text(json.dumps(manifest))
        store.ingest(self.connection, older)
        store.ingest(self.connection, newer)
        versions = dict(self.connection.execute("SELECT snapshot_id, tool_version FROM snapshots"))
        self.assertEqual(versions, {"20260901T090000Z": "1.1.0", "20260902T090000Z": "0.1.0"})

    def test_connecting_but_answering_nothing_is_not_producing_data(self):
        root = self.base / "20260901T090000Z"
        (root).mkdir(parents=True)
        (root / "manifest.json").write_text(json.dumps({
            "snapshot_id": "20260901T090000Z",
            "created_at": "2026-09-01T09:00:00+00:00",
            "devices": {"R1": {"name": "R1", "connected": True, "commands": [
                {"command": "show version", "status": "failed"},
            ]}},
            "summary": {},
        }))
        store.ingest(self.connection, root)
        row = self.connection.execute(
            "SELECT produced_data FROM devices WHERE name = 'R1'"
        ).fetchone()
        self.assertEqual(row["produced_data"], 0)

    def test_a_ping_alone_is_not_produced_data_either(self):
        root = self.base / "20260901T090000Z"
        root.mkdir(parents=True)
        (root / "manifest.json").write_text(json.dumps({
            "snapshot_id": "20260901T090000Z",
            "created_at": "2026-09-01T09:00:00+00:00",
            "devices": {"R1": {"name": "R1", "connected": True, "commands": [
                {"command": "ping 10.0.0.2", "status": "parsed"},
            ]}},
            "summary": {},
        }))
        store.ingest(self.connection, root)
        row = self.connection.execute(
            "SELECT produced_data FROM devices WHERE name = 'R1'"
        ).fetchone()
        self.assertEqual(row["produced_data"], 0)


class EstateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.connection = store.connect(store.default_path(self.base))
        write_snapshot(self.base, "20260901T090000Z", "2026-09-01T09:00:00+00:00", "unparsed")
        write_snapshot(self.base, "20260915T090000Z", "2026-09-15T09:00:00+00:00", "parsed")
        store.backfill(self.connection, self.base)

    def tearDown(self) -> None:
        self.connection.close()

    def test_backfill_ingests_every_directory_once(self):
        self.assertEqual(len(store.snapshot_ids(self.connection)), 2)
        # Running it again finds nothing new rather than duplicating everything.
        self.assertEqual(store.backfill(self.connection, self.base), [])

    def test_the_estate_counts_runs_and_answers_separately(self):
        rows = {row["name"]: row for row in store.estate(self.connection)}
        self.assertEqual(rows["R1"]["runs"], 2)
        self.assertEqual(rows["R1"]["answered_runs"], 2)
        # R2 was in both runs and answered in neither, which is exactly the
        # device an estate view exists to make visible.
        self.assertEqual(rows["R2"]["runs"], 2)
        self.assertEqual(rows["R2"]["answered_runs"], 0)

    def test_first_and_last_seen_bracket_the_runs(self):
        rows = {row["name"]: row for row in store.estate(self.connection)}
        self.assertEqual(rows["R1"]["first_seen"], "2026-09-01T09:00:00+00:00")
        self.assertEqual(rows["R1"]["last_seen"], "2026-09-15T09:00:00+00:00")

    def test_a_command_that_changed_outcome_is_found(self):
        # The query the directory layout could not answer.
        changes = store.compare_status(
            self.connection, "20260901T090000Z", "20260915T090000Z"
        )
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["command"], "show pim neighbor")
        self.assertEqual((changes[0]["was"], changes[0]["now"]), ("unparsed", "parsed"))

    def test_history_is_ordered_oldest_first(self):
        history = store.command_history(self.connection, "R1", "show pim neighbor")
        self.assertEqual([row["status"] for row in history], ["unparsed", "parsed"])

    def test_snapshots_come_back_newest_first(self):
        self.assertEqual(
            store.snapshot_ids(self.connection),
            ["20260915T090000Z", "20260901T090000Z"],
        )


class PrunedSnapshotTests(unittest.TestCase):
    """A snapshot with no files left still reads, through the database."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.root = write_snapshot(
            self.base, "20260915T090000Z", "2026-09-15T09:00:00+00:00", "unparsed"
        )
        connection = store.connect(store.default_path(self.base))
        store.ingest(connection, self.root)
        connection.close()
        self.removed = store.prune_files(self.root)

    def test_pruning_removes_the_per_command_files_and_nothing_else(self):
        self.assertEqual(self.removed, 3)
        self.assertFalse((self.root / "R1" / "raw").exists())
        self.assertFalse((self.root / "R1" / "state").exists())
        # The run's own record stays: it is not a duplicate of the database.
        self.assertTrue((self.root / "manifest.json").is_file())

    def test_parsed_state_still_reads(self):
        snapshot = Snapshot.load(self.root)
        self.assertIsNotNone(snapshot.db)
        self.assertEqual(
            snapshot.state("R1", "show version"),
            {"version": {"version": "17.09.04a", "platform": "CSR1000V"}},
        )

    def test_unparsed_raw_still_reads(self):
        snapshot = Snapshot.load(self.root)
        self.assertIn("10.0.0.2", snapshot.raw("R1", "show pim neighbor") or "")

    def test_nothing_downstream_can_tell_the_difference(self):
        snapshot = Snapshot.load(self.root)
        self.assertEqual(snapshot.device_names, ["R1"])
        self.assertEqual(snapshot.status("R1", "show version"), "parsed")

    def test_a_snapshot_with_no_database_falls_back_to_its_files(self):
        # The silent fallback matters: every snapshot taken before this existed
        # has to keep reading, and a warning on every read trains people to
        # ignore warnings.
        other = write_snapshot(
            Path(tempfile.mkdtemp()), "20260101T090000Z", "2026-01-01T09:00:00+00:00"
        )
        snapshot = Snapshot.load(other)
        self.assertIsNone(snapshot.db)
        self.assertIsNotNone(snapshot.state("R1", "show version"))

    def test_a_pruned_snapshot_read_without_its_database_says_so(self):
        """BUG-193: no files and no database is no data, not a network that answered nothing."""
        from netstate.collector import CollectionError

        elsewhere = Path(tempfile.mkdtemp()) / "disconet.db"
        with self.assertRaises(CollectionError) as caught:
            Snapshot.load(self.root, db=elsewhere)
        message = str(caught.exception)
        self.assertIn("pruned", message)
        self.assertIn(str(elsewhere), message)
        self.assertIn("--db", message)

    def test_a_pruned_snapshot_whose_database_was_moved_away_says_so(self):
        """BUG-193: the default database gone from beside the snapshots is the same case."""
        from netstate.collector import CollectionError

        store.default_path(self.base).rename(self.base.parent / "moved.db")
        with self.assertRaises(CollectionError):
            Snapshot.load(self.root)

    def test_re_ingesting_a_pruned_run_keeps_what_the_database_held(self):
        """BUG-052: a re-ingest re-read the pruned files and stored NULL over the only copy."""
        connection = store.connect(store.default_path(self.base))
        store.ingest(connection, self.root)
        connection.close()

        snapshot = Snapshot.load(self.root)
        self.addCleanup(snapshot.close)
        self.assertEqual(
            snapshot.state("R1", "show version"),
            {"version": {"version": "17.09.04a", "platform": "CSR1000V"}},
        )
        self.assertIn("10.0.0.2", snapshot.raw("R1", "show pim neighbor") or "")


    def test_from_db_reads_a_run_by_id(self):
        snapshot = Snapshot.from_db(
            store.default_path(self.base), "20260915T090000Z", root=self.root
        )
        self.assertEqual(snapshot.snapshot_id, "20260915T090000Z")
        self.assertEqual(snapshot.features, ("ospf", "multicast"))

    def test_from_db_on_an_unknown_run_says_which_command_lists_them(self):
        from netstate.collector import CollectionError

        with self.assertRaises(CollectionError) as caught:
            Snapshot.from_db(store.default_path(self.base), "nope")
        self.assertIn("db list", str(caught.exception))


class TheDatabaseFileStandsAlone(unittest.TestCase):
    """BUG-194: disconet.db copied on its own holds every run, with nothing left in -wal.

    The database runs in WAL mode, where a commit reaches the main file only
    at a checkpoint. After --db-only it is the only copy of the device output,
    and "one file that copies with cp" is a promise the estate relies on.
    """

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.path = store.default_path(self.base)

    def record(self, snapshot_id: str, created_at: str) -> None:
        from netstate.collector import record_snapshot

        root = write_snapshot(self.base, snapshot_id, created_at)
        manifest = json.loads((root / "manifest.json").read_text())
        record_snapshot(manifest, root, self.path, prune_files=True)

    def copied_alone(self) -> sqlite3.Connection:
        import shutil

        copy = Path(tempfile.mkdtemp()) / "copy.db"
        shutil.copyfile(self.path, copy)
        connection = sqlite3.connect(copy)
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        return connection

    def test_a_run_collected_with_db_only_is_in_the_file_itself(self):
        self.record("20260915T090000Z", "2026-09-15T09:00:00+00:00")
        copy = self.copied_alone()
        self.assertTrue(store.has_snapshot(copy, "20260915T090000Z"))
        self.assertIsNotNone(store.output(copy, "20260915T090000Z", "R1", "show version")["state"])

    def test_a_reader_left_open_does_not_keep_the_run_out_of_the_file(self):
        # discover holds the last round's snapshot open while the next round
        # collects into the same database.
        self.record("20260901T090000Z", "2026-09-01T09:00:00+00:00")
        held = Snapshot.load(self.base / "20260901T090000Z")
        self.addCleanup(held.close)
        self.assertIsNotNone(held.db)
        self.record("20260915T090000Z", "2026-09-15T09:00:00+00:00")
        self.assertTrue(store.has_snapshot(self.copied_alone(), "20260915T090000Z"))

    def test_a_snapshot_closes_its_connection(self):
        self.record("20260915T090000Z", "2026-09-15T09:00:00+00:00")
        snapshot = Snapshot.load(self.base / "20260915T090000Z")
        connection = snapshot.db
        snapshot.close()
        self.assertIsNone(snapshot.db)
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        snapshot.close()  # twice is not an error


class PruningKeepsWhatTheDatabaseCouldNotRead(unittest.TestCase):
    """BUG-295: --db-only deleted a file the ingest could not read, and the database held NULL for it.

    A file that is not UTF-8, or that the user cannot read, is stored as
    nothing; pruning it then deleted the only copy of what the device said.
    """

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.path = store.default_path(self.base)

    def record(self, snapshot_id: str, created_at: str, unreadable: bool) -> Path:
        from netstate.collector import record_snapshot

        root = write_snapshot(self.base, snapshot_id, created_at)
        if unreadable:
            (root / "R1" / "raw" / "show-pim-neighbor.txt").write_bytes(b"10.0.0.2 \xff\xfe Gi2\n")
        else:
            # A file the run never wrote is not one the database failed to read.
            (root / "R1" / "raw" / "show-pim-neighbor.txt").unlink()
        manifest = json.loads((root / "manifest.json").read_text())
        with self.assertLogs("netstate", level="INFO") as logs:
            record_snapshot(manifest, root, self.path, prune_files=True)
        self.logs = "\n".join(logs.output)
        return root

    def test_a_run_with_a_file_the_database_does_not_hold_keeps_its_files_and_says_why(self):
        root = self.record("20260915T090000Z", "2026-09-15T09:00:00+00:00", unreadable=True)
        self.assertTrue((root / "R1" / "raw" / "show-pim-neighbor.txt").is_file())
        self.assertTrue((root / "R1" / "state" / "show-version.json").is_file())
        self.assertFalse(store.files_pruned(root))
        self.assertIn("R1/raw/show-pim-neighbor.txt", self.logs)
        self.assertIn("WARNING", self.logs)

    def test_a_run_the_database_holds_whole_is_still_pruned(self):
        root = self.record("20260915T090000Z", "2026-09-15T09:00:00+00:00", unreadable=False)
        self.assertTrue(store.files_pruned(root))


class CopyOutputsTests(unittest.TestCase):
    """What merge needs: one device's outputs carried from one run to another."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.connection = store.connect(store.default_path(self.base))
        write_snapshot(self.base, "20260901T090000Z", "2026-09-01T09:00:00+00:00")
        write_snapshot(self.base, "20260915T090000Z", "2026-09-15T09:00:00+00:00")
        store.backfill(self.connection, self.base)

    def tearDown(self) -> None:
        self.connection.close()

    def test_outputs_carry_across_and_replace(self):
        copied = store.copy_outputs(
            self.connection, "20260901T090000Z", "20260915T090000Z", "R1"
        )
        self.assertEqual(copied, 2)
        # Twice is not an error and does not double anything.
        store.copy_outputs(
            self.connection, "20260901T090000Z", "20260915T090000Z", "R1"
        )
        rows = store.outputs_for(self.connection, "20260915T090000Z", "R1")
        self.assertEqual(len(rows), 2)

    def test_forgetting_a_run_takes_its_rows_with_it(self):
        self.assertTrue(store.forget(self.connection, "20260901T090000Z"))
        self.assertFalse(store.has_snapshot(self.connection, "20260901T090000Z"))
        self.assertEqual(
            store.outputs_for(self.connection, "20260901T090000Z", "R1"), []
        )
        self.assertFalse(store.forget(self.connection, "20260901T090000Z"))


class ReadOnlyAccessTests(unittest.TestCase):
    """Reading takes a read.

    `connect` runs the schema script, and a script of CREATE TABLE IF NOT
    EXISTS is still a write transaction. Doing that on every read is pointless
    on a normal database and a failure rather than a no-op on one held
    read-only — a snapshot on a mounted archive, or a database another writer
    has open.
    """

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.path = store.default_path(self.base)
        connection = store.connect(self.path)
        store.ingest(
            connection,
            write_snapshot(self.base, "20260915T090000Z", "2026-09-15T09:00:00+00:00"),
        )
        connection.close()

    def test_opening_for_reading_cannot_write(self):
        connection = store.open_existing(self.path)
        self.addCleanup(connection.close)
        self.assertTrue(store.has_snapshot(connection, "20260915T090000Z"))
        with self.assertRaises(sqlite3.OperationalError):
            connection.execute("DELETE FROM snapshots")

    def test_a_file_that_is_not_a_database_raises_rather_than_corrupting(self):
        not_a_database = self.base / "notes.txt"
        not_a_database.write_text("this is not a database")
        connection = store.open_existing(not_a_database)
        self.addCleanup(connection.close)
        with self.assertRaises(sqlite3.DatabaseError):
            store.has_snapshot(connection, "anything")

    def test_attaching_to_a_read_only_database_still_works(self):
        root = self.base / "20260915T090000Z"
        self.path.chmod(0o444)
        self.addCleanup(lambda: self.path.chmod(0o644))
        snapshot = Snapshot.load(root)
        self.assertIsNotNone(snapshot.db)
        self.assertIsNotNone(snapshot.state("R1", "show version"))


class TheDatabasePathIsAPathNotAURI(unittest.TestCase):
    """BUG-201: the read-only URI was built from the path unescaped.

    A '#' or '?' in a directory name (an estate called 'lab#2') ended the
    path early, so the read opened, or created, another file and found no
    runs; after a --db-only prune the run could not be read at all.
    """

    def database_under(self, directory: str) -> Path:
        base = Path(tempfile.mkdtemp()) / directory / "snapshots"
        base.mkdir(parents=True)
        connection = store.connect(store.default_path(base))
        store.ingest(
            connection,
            write_snapshot(base, "20260915T090000Z", "2026-09-15T09:00:00+00:00"),
        )
        connection.close()
        return base

    def test_a_directory_name_with_uri_characters_opens_the_database_in_it(self):
        for directory in ("lab#2", "lab?2", "lab%232", "lab 2"):
            with self.subTest(directory=directory):
                base = self.database_under(directory)
                connection = store.open_existing(store.default_path(base))
                self.addCleanup(connection.close)
                self.assertTrue(store.has_snapshot(connection, "20260915T090000Z"))
                # Nothing was opened, or left behind, at a truncated path.
                self.assertEqual(
                    sorted(path.name for path in base.parent.parent.iterdir()), [directory]
                )

    def test_a_pruned_run_there_still_reads_through_its_database(self):
        base = self.database_under("lab#2")
        root = base / "20260915T090000Z"
        store.prune_files(root)
        snapshot = Snapshot.load(root)
        self.addCleanup(snapshot.close)
        self.assertIsNotNone(snapshot.db)
        self.assertIsNotNone(snapshot.state("R1", "show version"))


class WhatTheReviewFoundInTheEstateTable(unittest.TestCase):
    """B3/E5, C6 and the split rows: counted runs, one row per box, a version guard."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.db = store.default_path(self.base)
        self.connection = store.connect(self.db)

    def tearDown(self) -> None:
        self.connection.close()

    def rows(self) -> dict:
        return {row["name"]: row for row in store.estate(self.connection)}

    def test_importing_the_same_run_twice_does_not_inflate_the_counters(self):
        write_snapshot(self.base, "run-1", "2026-09-01T09:00:00+00:00")
        for _ in range(3):
            store.ingest(self.connection, self.base / "run-1")
            store.update_estate(self.connection, "run-1")
        self.assertEqual(self.rows()["R1"]["runs"], 1)
        self.assertEqual(self.rows()["R1"]["answered_runs"], 1)

    def test_a_box_one_run_reached_under_two_names_counts_that_run_once(self):
        """BUG-294: the counters counted device rows, so one run showed as 2/2.

        A router swept at two of its addresses is two testbed entries in one
        run and one box by its serial; one of them answering is that box
        answering once.
        """
        root = write_snapshot(self.base, "run-1", "2026-09-01T09:00:00+00:00")
        manifest = json.loads((root / "manifest.json").read_text())
        manifest["devices"]["dev_10_0_0_1"] = manifest["devices"].pop("R1")
        manifest["devices"]["dev_10_0_0_2"] = manifest["devices"].pop("R2")
        (root / "manifest.json").write_text(json.dumps(manifest))
        store.ingest(self.connection, root)
        box = {"serial": "FDO1234", "hostname": "PE1"}
        store.update_estate(self.connection, "run-1", facts={"dev_10_0_0_1": box, "dev_10_0_0_2": box})
        rows = self.rows()
        self.assertEqual(list(rows), ["PE1"])
        self.assertEqual((rows["PE1"]["runs"], rows["PE1"]["answered_runs"]), (1, 1))

    def test_a_merged_run_is_not_counted_as_a_run(self):
        write_snapshot(self.base, "run-1", "2026-09-01T09:00:00+00:00")
        merged = write_snapshot(self.base, "merged", "2026-09-01T09:00:00+00:00")
        manifest = json.loads((merged / "manifest.json").read_text())
        manifest["merged_from"] = [{"snapshot_id": "run-1"}]
        (merged / "manifest.json").write_text(json.dumps(manifest))
        store.backfill(self.connection, self.base)
        self.assertEqual(self.rows()["R1"]["runs"], 1)
        flagged = self.connection.execute(
            "SELECT merged FROM snapshots WHERE snapshot_id = 'merged'"
        ).fetchone()["merged"]
        self.assertEqual(flagged, 1)

    def test_a_renamed_copy_of_a_run_is_the_same_run(self):
        original = write_snapshot(self.base, "run-1", "2026-09-01T09:00:00+00:00")
        copy = self.base / "before-upgrade"
        copy.mkdir()
        for path in original.rglob("*"):
            target = copy / path.relative_to(original)
            if path.is_dir():
                target.mkdir()
            else:
                target.write_bytes(path.read_bytes())
        self.assertEqual(store.backfill(self.connection, self.base), ["run-1"])
        self.assertEqual(store.backfill(self.connection, self.base), [])
        root = self.connection.execute(
            "SELECT root FROM snapshots WHERE snapshot_id = 'run-1'"
        ).fetchone()["root"]
        self.assertEqual(Path(root).name, "before-upgrade")  # the first directory seen, kept
        self.assertEqual(self.rows()["R1"]["runs"], 1)

    def test_a_placeholder_that_finalize_renamed_stays_one_row(self):
        first = write_snapshot(self.base, "run-1", "2026-09-01T09:00:00+00:00")
        manifest = json.loads((first / "manifest.json").read_text())
        manifest["devices"]["dev_10_0_0_1"] = manifest["devices"].pop("R1")
        (first / "manifest.json").write_text(json.dumps(manifest))
        store.ingest(self.connection, first)
        store.update_estate(self.connection, "run-1", facts={
            "dev_10_0_0_1": {"serial": "FDO1234", "hostname": "PE1", "mgmt_ip": "10.0.0.1"},
        })
        second = write_snapshot(self.base, "run-2", "2026-09-08T09:00:00+00:00")
        manifest = json.loads((second / "manifest.json").read_text())
        manifest["devices"]["PE1"] = manifest["devices"].pop("R1")
        (second / "manifest.json").write_text(json.dumps(manifest))
        store.ingest(self.connection, second)
        store.update_estate(self.connection, "run-2", facts={"PE1": {"serial": "FDO1234", "hostname": "PE1"}})
        rows = self.rows()
        self.assertNotIn("dev_10_0_0_1", rows)
        self.assertEqual(rows["PE1"]["runs"], 2)
        self.assertEqual(rows["PE1"]["answered_runs"], 2)
        self.assertEqual(rows["PE1"]["first_seen"], "2026-09-01T09:00:00+00:00")
        self.assertEqual(json.loads(rows["PE1"]["aliases"]), ["dev_10_0_0_1"])

    def test_a_box_reached_under_a_new_name_with_the_same_serial_is_the_same_row(self):
        write_snapshot(self.base, "run-1", "2026-09-01T09:00:00+00:00")
        store.ingest(self.connection, self.base / "run-1")
        store.update_estate(self.connection, "run-1", facts={"R1": {"serial": "A1, B2"}})
        second = write_snapshot(self.base, "run-2", "2026-09-08T09:00:00+00:00")
        manifest = json.loads((second / "manifest.json").read_text())
        manifest["devices"]["core-1"] = manifest["devices"].pop("R1")
        (second / "manifest.json").write_text(json.dumps(manifest))
        store.ingest(self.connection, second)
        store.update_estate(self.connection, "run-2", facts={"core-1": {"serial": "B2"}})
        rows = self.rows()
        self.assertEqual(len([n for n in rows if n != "R2"]), 1)
        (name,) = [n for n in rows if n != "R2"]
        self.assertEqual(rows[name]["runs"], 2)

    def test_two_devices_with_no_serial_and_no_address_stay_two_rows(self):
        write_snapshot(self.base, "run-1", "2026-09-01T09:00:00+00:00")
        store.backfill(self.connection, self.base)
        self.assertEqual(sorted(self.rows()), ["R1", "R2"])

    def test_a_database_from_a_newer_disconet_is_refused_with_a_message(self):
        self.connection.execute(
            "UPDATE schema_info SET value = ? WHERE key = 'version'", (str(store.SCHEMA_VERSION + 1),)
        )
        self.connection.commit()
        self.connection.close()
        with self.assertRaises(store.SchemaTooNew) as caught:
            store.connect(self.db)
        self.assertIn("newer DiscoNet", str(caught.exception))
        self.connection = store.connect(store.default_path(Path(tempfile.mkdtemp())))

    def test_a_version_one_database_is_migrated_and_its_split_rows_folded(self):
        self.connection.close()
        path = Path(tempfile.mkdtemp()) / "old.db"
        old = sqlite3.connect(str(path))
        old.executescript("""
            CREATE TABLE schema_info (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_info VALUES ('version', '1');
            CREATE TABLE snapshots (
                snapshot_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, ingested_at TEXT NOT NULL,
                root TEXT, testbed TEXT, tool_version TEXT, mode TEXT,
                demo INTEGER NOT NULL DEFAULT 0, features TEXT, features_skipped TEXT,
                devices_total INTEGER, devices_connected INTEGER, manifest TEXT NOT NULL);
            CREATE TABLE devices (
                snapshot_id TEXT NOT NULL, name TEXT NOT NULL, os TEXT, platform TEXT,
                connected INTEGER NOT NULL DEFAULT 0, produced_data INTEGER NOT NULL DEFAULT 0,
                error TEXT, connect_log TEXT, entry TEXT NOT NULL, PRIMARY KEY (snapshot_id, name));
            CREATE TABLE outputs (
                snapshot_id TEXT NOT NULL, device TEXT NOT NULL, command TEXT NOT NULL,
                status TEXT, detail TEXT, seconds REAL, raw TEXT, state TEXT,
                redacted_lines INTEGER, PRIMARY KEY (snapshot_id, device, command));
            CREATE TABLE estate_devices (
                name TEXT PRIMARY KEY, mgmt_ip TEXT, os TEXT, platform TEXT, software TEXT,
                serial TEXT, first_seen TEXT, last_seen TEXT, last_snapshot TEXT,
                runs INTEGER NOT NULL DEFAULT 0, answered_runs INTEGER NOT NULL DEFAULT 0);
            INSERT INTO snapshots VALUES ('run-1', '2026-09-01T09:00:00+00:00', 'x', 'r', 't', 'v', 'loose', 0, NULL, NULL, 1, 1, '{}');
            INSERT INTO snapshots VALUES ('run-2', '2026-09-08T09:00:00+00:00', 'x', 'r', 't', 'v', 'loose', 0, NULL, NULL, 1, 1, '{}');
            INSERT INTO snapshots VALUES ('merged', '2026-09-08T09:00:00+00:00', 'x', 'r', 't', 'v', 'loose', 0, NULL, NULL, 1, 1, '{"merged_from": [1]}');
            INSERT INTO devices VALUES ('run-1', 'dev_10_0_0_1', 'iosxe', NULL, 1, 1, NULL, NULL, '{}');
            INSERT INTO devices VALUES ('run-2', 'PE1', 'iosxe', NULL, 1, 1, NULL, NULL, '{}');
            INSERT INTO devices VALUES ('merged', 'PE1', 'iosxe', NULL, 1, 1, NULL, NULL, '{}');
            INSERT INTO estate_devices VALUES ('dev_10_0_0_1', '10.0.0.1', 'iosxe', NULL, NULL, 'FDO1', '2026-09-01T09:00:00+00:00', '2026-09-01T09:00:00+00:00', 'run-1', 7, 7);
            INSERT INTO estate_devices VALUES ('PE1', NULL, 'iosxe', 'CSR1000V', NULL, 'FDO1', '2026-09-08T09:00:00+00:00', '2026-09-08T09:00:00+00:00', 'run-2', 9, 9);
        """)
        old.commit()
        old.close()
        self.connection = store.connect(path)
        rows = self.rows()
        self.assertEqual(sorted(rows), ["PE1"])
        self.assertEqual(json.loads(rows["PE1"]["aliases"]), ["dev_10_0_0_1"])
        self.assertEqual(rows["PE1"]["first_seen"], "2026-09-01T09:00:00+00:00")
        self.assertEqual(rows["PE1"]["mgmt_ip"], "10.0.0.1")
        self.assertEqual(rows["PE1"]["platform"], "CSR1000V")
        self.assertEqual((rows["PE1"]["runs"], rows["PE1"]["answered_runs"]), (2, 2))
        self.assertEqual(store.stored_version(self.connection), store.SCHEMA_VERSION)


class LastSeenIsTheLastRunTheDeviceAnsweredIn(unittest.TestCase):
    """BUG-153: every run a device was in moved its last-seen, answered or not.

    A device that had stopped answering, or that a merged run carried
    forward, looked as current in `db estate` as one collected that morning.
    """

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.connection = store.connect(store.default_path(self.base))

    def tearDown(self) -> None:
        self.connection.close()

    def rows(self) -> dict:
        return {row["name"]: row for row in store.estate(self.connection)}

    def ingest(
        self, snapshot_id: str, created_at: str, connected: bool = True, merged: bool = False,
        source: str = "run-1",
    ) -> None:
        root = write_snapshot(self.base, snapshot_id, created_at, connected=connected)
        if merged:
            manifest = json.loads((root / "manifest.json").read_text())
            manifest["merged_from"] = [{"snapshot_id": source}]
            (root / "manifest.json").write_text(json.dumps(manifest))
        store.ingest(self.connection, root)
        store.update_estate(self.connection, snapshot_id)

    def test_a_device_that_stopped_answering_was_last_seen_when_it_last_answered(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        self.ingest("run-2", "2026-09-15T09:00:00+00:00", connected=False)
        row = self.rows()["R1"]
        self.assertEqual((row["last_seen"], row["last_snapshot"]), ("2026-09-01T09:00:00+00:00", "run-1"))
        self.assertEqual(row["first_seen"], "2026-09-01T09:00:00+00:00")
        self.assertEqual((row["answered_runs"], row["runs"]), (1, 2))

    def test_a_device_that_never_answered_has_never_been_seen(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        row = self.rows()["R2"]
        self.assertIsNone(row["last_seen"])
        self.assertIsNone(row["last_snapshot"])
        self.assertEqual(row["first_seen"], "2026-09-01T09:00:00+00:00")

    def test_its_first_answer_after_runs_without_one_is_its_last_seen(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00", connected=False)
        self.ingest("run-2", "2026-09-15T09:00:00+00:00")
        row = self.rows()["R1"]
        self.assertEqual((row["last_seen"], row["last_snapshot"]), ("2026-09-15T09:00:00+00:00", "run-2"))
        self.assertEqual(row["first_seen"], "2026-09-01T09:00:00+00:00")

    def test_a_merged_run_does_not_move_it(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        self.ingest("merged", "2026-09-15T09:00:00+00:00", merged=True)
        row = self.rows()["R1"]
        self.assertEqual((row["last_seen"], row["last_snapshot"]), ("2026-09-01T09:00:00+00:00", "run-1"))

    def ingest_with_facts(self, snapshot_id: str, created_at: str, facts: dict) -> None:
        root = write_snapshot(self.base, snapshot_id, created_at)
        store.ingest(self.connection, root)
        store.update_estate(self.connection, snapshot_id, facts={"R1": facts})

    def test_an_older_run_imported_later_does_not_rewrite_its_facts(self):
        """S4-03: `db import` of an archived March run put March's software and serial on the row."""
        self.ingest_with_facts(
            "run-2", "2026-09-01T09:00:00+00:00",
            {"software": "7.11.2", "serial": "FOC2222BBBB", "mgmt_ip": "192.0.2.2"},
        )
        self.ingest_with_facts(
            "run-1", "2026-03-01T09:00:00+00:00",
            {"software": "6.5.3", "serial": "FOC1111AAAA", "mgmt_ip": "192.0.2.1"},
        )
        row = self.rows()["R1"]
        self.assertEqual(
            (row["software"], row["serial"], row["mgmt_ip"]), ("7.11.2", "FOC2222BBBB", "192.0.2.2")
        )
        self.assertEqual((row["last_snapshot"], row["first_seen"]), ("run-2", "2026-03-01T09:00:00+00:00"))

    def test_an_older_run_still_gives_a_fact_no_newer_one_did(self):
        """S4-03: what only the old run read is still the newest word on it, as forget's re-read keeps it."""
        self.ingest_with_facts("run-2", "2026-09-01T09:00:00+00:00", {"software": "7.11.2"})
        self.ingest_with_facts("run-1", "2026-03-01T09:00:00+00:00", {"software": "6.5.3", "serial": "FOC1111AAAA"})
        row = self.rows()["R1"]
        self.assertEqual((row["software"], row["serial"]), ("7.11.2", "FOC1111AAAA"))

    def test_a_newer_run_still_replaces_them(self):
        self.ingest_with_facts("run-1", "2026-03-01T09:00:00+00:00", {"software": "6.5.3", "serial": "FOC1111AAAA"})
        self.ingest_with_facts("run-2", "2026-09-01T09:00:00+00:00", {"software": "7.11.2", "serial": "FOC1111AAAA"})
        self.assertEqual(self.rows()["R1"]["software"], "7.11.2")


class TheForgetCommand(unittest.TestCase):
    """`disconet db forget`: a run dropped from the database, its directory only when asked."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        connection = store.connect(store.default_path(self.base))
        write_snapshot(self.base, "20260901T090000Z", "2026-09-01T09:00:00+00:00")
        write_snapshot(self.base, "20260915T090000Z", "2026-09-15T09:00:00+00:00")
        store.backfill(connection, self.base)
        connection.close()


    def held(self) -> list[str]:
        connection = store.open_existing(store.default_path(self.base))
        try:
            return store.snapshot_ids(connection)
        finally:
            connection.close()


    def test_a_run_ingested_by_a_relative_path_records_where_it_is(self):
        """S4-02: `collect --estate` ingests estates/<name>/snapshots/<id>, which only finds it from one directory."""
        write_snapshot(self.base, "20260920T090000Z", "2026-09-20T09:00:00+00:00")
        cwd = os.getcwd()
        os.chdir(self.base.parent)
        self.addCleanup(os.chdir, cwd)
        connection = store.connect(Path("snapshots") / store.default_path(self.base).name)
        try:
            store.ingest(connection, Path("snapshots") / "20260920T090000Z")
            recorded = store.recorded_root(connection, "20260920T090000Z")
        finally:
            connection.close()
        self.assertTrue(recorded.is_absolute(), recorded)
        self.assertEqual(recorded, (self.base / "20260920T090000Z").resolve())


    def merge_of(self, merge_id: str, *sources: str) -> None:
        """A merged run made from ``sources``, held in the database as `merge` would leave it."""
        root = write_snapshot(self.base, merge_id, "2026-09-15T09:00:00+00:00")
        manifest = json.loads((root / "manifest.json").read_text())
        manifest["merged_from"] = [{"snapshot_id": source} for source in sources]
        (root / "manifest.json").write_text(json.dumps(manifest))
        connection = store.connect(store.default_path(self.base))
        try:
            store.ingest(connection, root)
        finally:
            connection.close()


    def test_the_library_refuses_too(self):
        self.merge_of("20260916T000000Z", "20260901T090000Z")
        connection = store.connect(store.default_path(self.base))
        try:
            with self.assertRaises(store.RunInMerge) as refused:
                store.forget(connection, "20260901T090000Z")
            self.assertEqual(refused.exception.merges, ["20260916T000000Z"])
            self.assertTrue(store.has_snapshot(connection, "20260901T090000Z"))
        finally:
            connection.close()


class AForgottenRunLeavesTheEstateInventoryToo(LastSeenIsTheLastRunTheDeviceAnsweredIn):
    """BUG-199: `db forget` dropped the run and left its devices in the estate inventory.

    The counts went on counting it, the seen-dates and last snapshot went on
    naming it, and a device only it had reached stayed listed.
    """

    def test_a_device_only_the_forgotten_run_reached_is_no_longer_listed(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        self.assertTrue(store.forget(self.connection, "run-1"))
        self.assertEqual(self.rows(), {})

    def test_the_runs_left_are_counted_again(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        self.ingest("run-2", "2026-09-15T09:00:00+00:00")
        store.forget(self.connection, "run-2")
        rows = self.rows()
        self.assertEqual((rows["R1"]["runs"], rows["R1"]["answered_runs"]), (1, 1))
        self.assertEqual((rows["R2"]["runs"], rows["R2"]["answered_runs"]), (1, 0))

    def test_its_last_seen_is_the_last_run_left_that_it_answered_in(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        self.ingest("run-2", "2026-09-15T09:00:00+00:00")
        store.forget(self.connection, "run-2")
        row = self.rows()["R1"]
        self.assertEqual((row["last_seen"], row["last_snapshot"]), ("2026-09-01T09:00:00+00:00", "run-1"))

    def test_its_first_seen_is_the_first_run_left(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        self.ingest("run-2", "2026-09-15T09:00:00+00:00")
        store.forget(self.connection, "run-1")
        rows = self.rows()
        self.assertEqual(rows["R1"]["first_seen"], "2026-09-15T09:00:00+00:00")
        self.assertEqual(rows["R2"]["first_seen"], "2026-09-15T09:00:00+00:00")
        self.assertIsNone(rows["R2"]["last_seen"])

    def test_the_facts_a_forgotten_run_gave_go_with_it(self):
        """S-11: a run of the wrong network left its serial, software and platform on R1.

        The counts and dates were read again from the runs left, and the
        facts were not: the documented use of forget is exactly that run.
        """
        ours = {"R1": {"serial": "FDO1111AAAA", "software": "17.9.4", "platform": "CSR1000V"}}
        wrong = {"R1": {"serial": "FOX9999ZZZZ", "software": "7.5.2", "platform": "ASR9006"}}
        root = write_snapshot(self.base, "run-1", "2026-09-01T09:00:00+00:00")
        store.ingest(self.connection, root)
        store.update_estate(self.connection, "run-1", facts=ours)
        root = write_snapshot(self.base, "run-2", "2026-09-02T09:00:00+00:00")
        manifest = json.loads((root / "manifest.json").read_text())
        manifest["devices"]["R1"]["platform"] = "ASR9006"
        (root / "manifest.json").write_text(json.dumps(manifest))
        store.ingest(self.connection, root)
        store.update_estate(self.connection, "run-2", facts=wrong)
        self.assertEqual(self.rows()["R1"]["serial"], "FOX9999ZZZZ")

        store.forget(self.connection, "run-2")
        row = self.rows()["R1"]
        self.assertEqual(
            (row["serial"], row["software"], row["platform"]), ("FDO1111AAAA", "17.9.4", "CSR1000V")
        )

    def test_a_fact_only_the_forgotten_run_gave_is_not_kept(self):
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        root = write_snapshot(self.base, "run-2", "2026-09-02T09:00:00+00:00")
        store.ingest(self.connection, root)
        store.update_estate(self.connection, "run-2", facts={"R1": {"serial": "FOX9999ZZZZ"}})
        store.forget(self.connection, "run-2")
        self.assertIsNone(self.rows()["R1"]["serial"])

    def test_a_device_a_merged_run_still_holds_stays_listed_but_unseen(self):
        # A merge of runs the database never held: a run it was made from is
        # not forgotten while it is held (F-23).
        self.ingest("run-1", "2026-09-01T09:00:00+00:00")
        self.ingest("merged", "2026-09-15T09:00:00+00:00", merged=True, source="run-0")
        store.forget(self.connection, "run-1")
        row = self.rows()["R1"]
        self.assertEqual((row["runs"], row["last_seen"], row["last_snapshot"]), (0, None, None))


class TheDiffComparesBoxesNotRows(unittest.TestCase):
    """BUG-119: `db diff` printed the all-clear when a device stopped answering or was renamed.

    An inner join on (device, command) dropped a device with no outputs and
    a placeholder finalize renamed, then reported that nothing changed.
    """

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp()) / "snapshots"
        self.base.mkdir(parents=True)
        self.db = store.default_path(self.base)
        self.connection = store.connect(self.db)
        self.addCleanup(self.connection.close)

    def run_of(self, snapshot_id: str, devices: dict, facts: dict | None = None) -> None:
        """A run in the database: each device's commands and outcomes, or None for no answer."""
        root = self.base / snapshot_id
        root.mkdir()
        manifest = {
            "snapshot_id": snapshot_id,
            "created_at": f"2026-09-{snapshot_id[6:8]}T09:00:00+00:00",
            "devices": {
                name: {
                    "name": name, "os": "iosxe", "connected": commands is not None,
                    "error": None if commands is not None else "connect failed: timed out",
                    "commands": [{"command": command, "status": status}
                                 for command, status in (commands or {}).items()],
                }
                for name, commands in devices.items()
            },
            "summary": {},
        }
        (root / "manifest.json").write_text(json.dumps(manifest))
        store.ingest(self.connection, root)
        store.update_estate(self.connection, snapshot_id, facts=facts)

    OUTCOMES = {"show version": "parsed", "show pim neighbor": "unparsed"}

    def test_a_device_that_stopped_answering_is_a_change(self):
        self.run_of("20260901T090000Z", {"pe-1": self.OUTCOMES, "pe-2": self.OUTCOMES})
        self.run_of("20260915T090000Z", {"pe-1": self.OUTCOMES, "pe-2": None})

        changes = store.compare_status(self.connection, "20260901T090000Z", "20260915T090000Z")
        self.assertEqual(
            [(c["device"], c["command"], c["was"], c["now"]) for c in changes],
            [("pe-2", "show pim neighbor", "unparsed", None), ("pe-2", "show version", "parsed", None)],
        )
        devices = store.compare_devices(self.connection, "20260901T090000Z", "20260915T090000Z")
        self.assertEqual([(d["device"], d["was"], d["now"]) for d in devices],
                         [("pe-2", "answered", "did not answer")])

    def test_a_renamed_placeholder_is_compared_with_itself(self):
        self.run_of("20260901T090000Z", {"dev_10_0_0_11": self.OUTCOMES},
                    facts={"dev_10_0_0_11": {"hostname": "pe-1"}})
        self.run_of("20260915T090000Z", {"pe-1": {**self.OUTCOMES, "show pim neighbor": "parsed"}},
                    facts={"pe-1": {"hostname": "pe-1"}})

        changes = store.compare_status(self.connection, "20260901T090000Z", "20260915T090000Z")
        self.assertEqual([(c["device"], c["command"], c["was"], c["now"]) for c in changes],
                         [("pe-1", "show pim neighbor", "unparsed", "parsed")])
        devices = store.compare_devices(self.connection, "20260901T090000Z", "20260915T090000Z")
        self.assertEqual([(d["device"], d["was"], d["now"]) for d in devices],
                         [("pe-1", "answered as dev_10_0_0_11", "answered")])

    def test_a_device_new_in_the_later_run_is_a_change(self):
        self.run_of("20260901T090000Z", {"pe-1": self.OUTCOMES})
        self.run_of("20260915T090000Z", {"pe-1": self.OUTCOMES, "pe-3": self.OUTCOMES})
        devices = store.compare_devices(self.connection, "20260901T090000Z", "20260915T090000Z")
        self.assertEqual([(d["device"], d["was"], d["now"]) for d in devices],
                         [("pe-3", "not in the run", "answered")])


class ARelativeSnapshotPathFindsItsDatabase(unittest.TestCase):
    """BUG-100: `--snapshot .` looked for the database beside '.' rather than beside the snapshots.

    Read from inside the snapshot, '.' was its own parent, so a run pruned
    to the database it shares with the estate's other runs found none.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        base = Path(tmp.name) / "snapshots"
        base.mkdir()
        self.root = write_snapshot(base, "20260915T090000Z", "2026-09-15T09:00:00+00:00", "unparsed")
        connection = store.connect(store.default_path(base))
        store.ingest(connection, self.root)
        connection.close()
        store.prune_files(self.root)

    def read(self, path):
        snapshot = Snapshot.load(path)
        self.addCleanup(snapshot.close)
        return snapshot

    def test_dot_reads_through_the_database(self):
        os.chdir(self.root)
        snapshot = self.read(".")
        self.assertIsNotNone(snapshot.db)
        self.assertEqual(snapshot.status("R1", "show version"), "parsed")

    def test_a_bare_id_reads_through_the_database(self):
        os.chdir(self.root.parent)
        self.assertIsNotNone(self.read(self.root.name).db)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
