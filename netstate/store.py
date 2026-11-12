"""The estate database: every run of every device, in one SQLite file.

DiscoNet used to keep a run as a directory of text — ``raw/*.txt`` for what the
device said, ``state/*.json`` for what Genie made of it, ``manifest.json`` tying
them together. That is a fine record of one run and a poor record of an estate.
Nothing could answer "when did this adjacency last exist", "which devices have
ever refused this command", or "what changed since March" without a shell loop
over directories, and the loop had to know the layout.

This module puts the same facts in rows. One database per estate, not per run:
``snapshots`` is a table, not a directory name, so a query spans every run the
estate has ever had. That is what makes drift visible at all, and it is the
foundation the follow-up tooling is meant to build on.

Three properties are deliberate:

* **stdlib only.** ``sqlite3`` ships with Python. No server, no driver, no
  connection string — one file that copies with ``cp`` and opens on a laptop
  with no network. That matters now because it keeps the install simple, and it
  matters more later: a packaged Windows build cannot carry a database engine.
* **The manifest stays verbatim.** Every row this module derives is also
  recoverable from the ``manifest`` column, which holds the manifest JSON
  unaltered. A schema mistake here therefore costs a re-ingest, never data.
* **Ingest happens after the run, in one transaction.** Collection is threaded
  and SQLite connections are not, so writing rows from five worker threads
  would mean either a lock convoy or a connection per thread. Reading the files
  the run already wrote, once, costs a second on a large estate and makes the
  database atomic: it holds a whole run or none of it. It also means an old
  snapshot directory ingests through exactly the same code path as a fresh one,
  which is why backfill is three lines rather than a second implementation.

Raw text is stored the same way parsed state is — a column, not a file. An
unparsed output is the one most likely to matter later (it is usually a command
Genie has no schema for, on the platform you care about), so it is the last
thing that should be left outside the queryable store.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from netstate import private

log = logging.getLogger(__name__)

# The estate database lives beside the snapshot directories rather than inside
# one of them: it belongs to the estate, and a snapshot directory can be deleted
# without taking the history with it.
DEFAULT_DB_NAME = "disconet.db"

SCHEMA_VERSION = 2


class SchemaTooNew(sqlite3.Error):
    """The database was written by a newer DiscoNet than this one.

    A subclass of ``sqlite3.Error`` so every caller that already treats "the
    database is unavailable" as a warning treats this the same way, with a
    message that says what to do instead of a silent misread of newer rows.
    """


# The name a device wears before it has said its hostname. Duplicated from
# collector on purpose, for the same reason as the statuses below.
_PLACEHOLDER = re.compile(r"^dev_[0-9A-Fa-f_]+$")

# Statuses that mean the device answered. Duplicated from collector.Snapshot on
# purpose: importing collector here would drag pyATS into a module whose whole
# point is to be importable without it.
ANSWERED = frozenset({"parsed", "empty", "unparsed", "raw"})


SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS schema_info (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One row per collection run.
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id      TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    ingested_at      TEXT NOT NULL,
    root             TEXT,
    testbed          TEXT,
    tool_version     TEXT,
    mode             TEXT,
    demo             INTEGER NOT NULL DEFAULT 0,
    merged           INTEGER NOT NULL DEFAULT 0,
    features         TEXT,
    features_skipped TEXT,
    devices_total    INTEGER,
    devices_connected INTEGER,
    manifest         TEXT NOT NULL
);

-- One row per device per run. `entry` is that device's manifest block verbatim.
CREATE TABLE IF NOT EXISTS devices (
    snapshot_id   TEXT NOT NULL,
    name          TEXT NOT NULL,
    os            TEXT,
    platform      TEXT,
    connected     INTEGER NOT NULL DEFAULT 0,
    produced_data INTEGER NOT NULL DEFAULT 0,
    error         TEXT,
    connect_log   TEXT,
    entry         TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, name),
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id) ON DELETE CASCADE
);

-- One row per command per device per run. Both the redacted raw text and the
-- parsed state are columns here; neither needs a file to exist to be read.
CREATE TABLE IF NOT EXISTS outputs (
    snapshot_id    TEXT NOT NULL,
    device         TEXT NOT NULL,
    command        TEXT NOT NULL,
    status         TEXT,
    detail         TEXT,
    seconds        REAL,
    redacted_lines INTEGER NOT NULL DEFAULT 0,
    raw            TEXT,
    state          TEXT,
    PRIMARY KEY (snapshot_id, device, command),
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS outputs_by_command ON outputs(command);
CREATE INDEX IF NOT EXISTS outputs_by_device  ON outputs(device);
CREATE INDEX IF NOT EXISTS outputs_by_status  ON outputs(status);

-- The estate as a standing thing rather than a sequence of runs: what each
-- device is, when it was first and last seen answering, how many runs have
-- reached it. This is the table that makes the database worth keeping between
-- runs, and the one a later tool reads to know what the estate contains.
--
-- One row is one box, not one testbed name. `name` is the hostname the device
-- gave where it gave one, and `aliases` (a JSON list) holds every other name
-- runs have reached it under, so a placeholder that finalize renamed does not
-- start a second row. `runs` and `answered_runs` are counted from `devices`
-- over all of those names, never incremented, so re-ingesting a run cannot
-- inflate them.
CREATE TABLE IF NOT EXISTS estate_devices (
    name          TEXT PRIMARY KEY,
    aliases       TEXT,
    mgmt_ip       TEXT,
    os            TEXT,
    platform      TEXT,
    software      TEXT,
    serial        TEXT,
    first_seen    TEXT,
    last_seen     TEXT,
    last_snapshot TEXT,
    runs          INTEGER NOT NULL DEFAULT 0,
    answered_runs INTEGER NOT NULL DEFAULT 0
);

-- What each run told the estate table about a device that its manifest does
-- not hold: the facts update_estate was given. Kept so that forgetting a run
-- can take back what it said (a run of the wrong network left its serial and
-- software on the row), and gone with the run. A run stored before this
-- table existed has no rows here, and the row keeps what it had.
CREATE TABLE IF NOT EXISTS device_facts (
    snapshot_id TEXT NOT NULL,
    name        TEXT NOT NULL,
    mgmt_ip     TEXT,
    platform    TEXT,
    software    TEXT,
    serial      TEXT,
    PRIMARY KEY (snapshot_id, name),
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id) ON DELETE CASCADE
);
"""


def default_path(base_dir: Path | str) -> Path:
    """Where the estate database sits for a given snapshot base directory."""
    return Path(base_dir) / DEFAULT_DB_NAME


def open_existing(path: Path | str) -> sqlite3.Connection:
    """Open a database that already exists, without touching its schema.

    The read path. :func:`connect` runs the schema script, and a script full of
    CREATE TABLE IF NOT EXISTS is still a write transaction — pointless on
    every read, and a failure rather than a no-op on a database opened from a
    read-only mount or held by another writer. Reading takes a read.

    Raises ``sqlite3.Error`` if the file is not a database, which the caller
    treats as "no database here" and falls back to the files.
    """
    # A URI, so the path is escaped: a '#' or '?' in a directory name (an
    # estate called 'lab#2') would otherwise end the path and open another file.
    uri = Path(path).absolute().as_uri()
    connection = sqlite3.connect(f"{uri}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def open_reader(path: Path | str) -> sqlite3.Connection:
    """Open an existing estate database for a command that only reads it.

    Read-only when the file is at this schema. One written by an older
    DiscoNet is brought up to it first, which is a write, because the queries
    are this version's; one from a newer DiscoNet is refused as :func:`connect`
    refuses it. Nothing is ever created: the caller checks the file is there.

    Raises ``sqlite3.Error`` for a file that is not an estate database.
    """
    connection = open_existing(path)
    try:
        stored = stored_version(connection)
    except sqlite3.Error:
        connection.close()
        raise
    if stored == SCHEMA_VERSION:
        return connection
    connection.close()
    if stored is None:
        raise sqlite3.DatabaseError(f"{path} is not an estate database")
    return connect(path)


def connect(path: Path | str) -> sqlite3.Connection:
    """Open the estate database, creating and migrating it if need be.

    Rows come back as ``sqlite3.Row`` so callers index by column name; a schema
    that grows a column should not silently change what ``row[3]`` means.
    """
    path = Path(path)
    private.make_dir(path.parent)
    if not path.exists():
        # Made 0600 before SQLite opens it: SQLite gives its -wal and -shm
        # files the database's own mode, so they are owner-only too.
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT, private.FILE_MODE))
    private.secure_sqlite(path)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    stored = stored_version(connection)
    if stored is not None and stored > SCHEMA_VERSION:
        connection.close()
        raise SchemaTooNew(
            f"{path} was written by a newer DiscoNet (schema version {stored}; "
            f"this one reads up to {SCHEMA_VERSION}). Upgrade DiscoNet, or point "
            f"--db at another file."
        )
    connection.executescript(SCHEMA)
    _migrate(connection, stored)
    connection.execute(
        "INSERT OR REPLACE INTO schema_info(key, value) VALUES ('version', ?)",
        (str(SCHEMA_VERSION),),
    )
    connection.commit()
    return connection


def checkpoint_and_close(connection: sqlite3.Connection) -> None:
    """Close a writer with everything it wrote in the database file itself.

    In WAL mode a commit lands in disconet.db-wal and reaches disconet.db only
    at a checkpoint. SQLite checkpoints when the last connection closes, but
    not while a reader is still open, and a read-only reader cannot do it
    later. Copying disconet.db alone then loses those runs, and after
    --db-only they exist nowhere else. TRUNCATE also empties the log.
    """
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:  # noqa: BLE001 - SQLite checkpoints again when it can
        log.debug("could not checkpoint the estate database", exc_info=True)
    finally:
        connection.close()


def stored_version(connection: sqlite3.Connection) -> int | None:
    """The schema version the file records, or None for a file with no schema yet."""
    try:
        row = connection.execute(
            "SELECT value FROM schema_info WHERE key = 'version'"
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    try:
        return int(row["value"])
    except (TypeError, ValueError):
        return None


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}


def _migrate(connection: sqlite3.Connection, stored: int | None) -> None:
    """Bring a database written by an older DiscoNet up to this schema.

    Columns are added rather than tables rebuilt, and every derived value is
    recomputed from the rows that are still there: the manifest is verbatim, so
    nothing this does can lose what the run recorded.
    """
    if "merged" not in _columns(connection, "snapshots"):
        connection.execute(
            "ALTER TABLE snapshots ADD COLUMN merged INTEGER NOT NULL DEFAULT 0"
        )
        for row in connection.execute("SELECT snapshot_id, manifest FROM snapshots").fetchall():
            try:
                merged = bool((json.loads(row["manifest"]) or {}).get("merged_from"))
            except (TypeError, ValueError):
                merged = False
            if merged:
                connection.execute(
                    "UPDATE snapshots SET merged = 1 WHERE snapshot_id = ?",
                    (row["snapshot_id"],),
                )
    if "aliases" not in _columns(connection, "estate_devices"):
        connection.execute("ALTER TABLE estate_devices ADD COLUMN aliases TEXT")
    if stored is not None and stored < 2:
        _fold_duplicates(connection)
        for row in connection.execute("SELECT name FROM estate_devices").fetchall():
            _recount(connection, row["name"])
    connection.commit()


def _json_or_none(value: Any) -> str | None:
    return None if value is None else json.dumps(value, sort_keys=True)


def _read_text(root: Path, relative: str | None) -> str | None:
    """Text of a file the manifest points at, or None if it is not there.

    A snapshot whose files were pruned after ingest, or moved, or never written
    because a command failed, is an ordinary case rather than an error: the row
    simply carries no raw text.
    """
    if not relative:
        return None
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        log.debug("could not read %s", path, exc_info=True)
        return None


def _read_json(root: Path, relative: str | None) -> str | None:
    """Parsed state as a JSON string, kept as text so it round-trips exactly."""
    text = _read_text(root, relative)
    if text is None:
        return None
    try:
        json.loads(text)
    except json.JSONDecodeError:
        log.warning("%s is not valid JSON; stored as-is", root / str(relative))
    return text


def _produced_data(entry: dict[str, Any]) -> bool:
    """Did this device answer anything at all? Mirrors Snapshot.produced_data.

    Connecting is not collecting, and the count of collected devices ends up in
    a document as a fact, so the database records the same judgement the rest of
    the tool makes rather than a looser one.
    """
    if not entry.get("connected"):
        return False
    return any(
        command.get("status") in ANSWERED
        for command in entry.get("commands", [])
        if not str(command.get("command", "")).startswith("ping ")
    )


def ingest(
    connection: sqlite3.Connection,
    snapshot_root: Path | str,
    manifest: dict[str, Any] | None = None,
) -> int:
    """Store one snapshot directory in the database. Returns rows of output.

    Re-ingesting the same snapshot replaces it rather than duplicating it, so
    this is safe to repeat — after a `merge`, say, or after a backfill that was
    interrupted. A file that is gone leaves the text the database already held
    for it: a run pruned after ingest has no files left, and reading it again
    must not replace the only copy with nothing. The whole thing is one
    transaction: a crash leaves the previous state, never half a run.
    """
    snapshot_root = Path(snapshot_root)
    if manifest is None:
        manifest_path = snapshot_root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    snapshot_id = str(manifest.get("snapshot_id") or snapshot_root.name)
    summary = manifest.get("summary") or {}
    now = datetime.now(timezone.utc).isoformat()
    rows = 0

    with connection:  # one transaction; commits on success, rolls back on error
        held = {
            (row["device"], row["command"]): row
            for row in connection.execute(
                "SELECT device, command, raw, state FROM outputs WHERE snapshot_id = ?",
                (snapshot_id,),
            )
        }
        connection.execute("DELETE FROM snapshots WHERE snapshot_id = ?", (snapshot_id,))
        connection.execute(
            """
            INSERT INTO snapshots (
                snapshot_id, created_at, ingested_at, root, testbed, tool_version,
                mode, demo, merged, features, features_skipped,
                devices_total, devices_connected, manifest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                str(manifest.get("created_at") or ""),
                now,
                # Resolved: `collect --estate` hands over the relative
                # estates/<name>/snapshots/<id>, which finds the run from the
                # directory the collect ran in and nowhere else, and a
                # `db forget --db` from a cron job then missed its pruned files.
                str(snapshot_root.resolve()),
                str(manifest.get("testbed") or ""),
                # The engine that collected the run; a run collected before the
                # engine had its own package says which DiscoNet did.
                str(
                    manifest.get("netstate_version") or manifest.get("disconet_version")
                    or manifest.get("version") or ""
                ),
                str(manifest.get("mode") or ""),
                1 if manifest.get("demo") else 0,
                1 if manifest.get("merged_from") else 0,
                _json_or_none(manifest.get("features")),
                _json_or_none(manifest.get("features_skipped")),
                summary.get("devices_total"),
                summary.get("devices_connected"),
                json.dumps(manifest, sort_keys=True),
            ),
        )

        for name, entry in (manifest.get("devices") or {}).items():
            # Outputs are stored under the name the testbed and the files
            # use, which is the one Snapshot reads them by. A merged run calls
            # a device by the hostname it learned and keeps that name beside
            # it; stored under the hostname, its rows were never found.
            stored = str(entry.get("testbed_name") or name)
            connection.execute(
                """
                INSERT INTO devices (
                    snapshot_id, name, os, platform, connected, produced_data,
                    error, connect_log, entry
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    name,
                    entry.get("os"),
                    entry.get("platform"),
                    1 if entry.get("connected") else 0,
                    1 if _produced_data(entry) else 0,
                    entry.get("error"),
                    entry.get("connect_log"),
                    json.dumps(entry, sort_keys=True),
                ),
            )
            for command in entry.get("commands") or []:
                text = str(command.get("command", ""))
                raw = _read_text(snapshot_root, command.get("raw_file"))
                state = _read_json(snapshot_root, command.get("state_file"))
                before = held.get((stored, text))
                if before is not None:
                    raw = before["raw"] if raw is None else raw
                    state = before["state"] if state is None else state
                connection.execute(
                    """
                    INSERT OR REPLACE INTO outputs (
                        snapshot_id, device, command, status, detail, seconds,
                        redacted_lines, raw, state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        stored,
                        text,
                        command.get("status"),
                        command.get("detail"),
                        command.get("seconds"),
                        command.get("redacted_lines") or 0,
                        raw,
                        state,
                    ),
                )
                rows += 1

    log.info("ingested %s into the estate database (%d output row(s))", snapshot_id, rows)
    return rows


def copy_outputs(
    connection: sqlite3.Connection,
    source_snapshot: str,
    target_snapshot: str,
    device: str,
    held_in: sqlite3.Connection | None = None,
) -> int:
    """Carry one device's stored outputs from one run into another.

    What `disconet merge` needs. A merged snapshot takes each device whole from
    whichever run answered for it, and the files are copied on disk — but a run
    collected with `--db-only` has no files to copy, and even one that has them
    would otherwise leave the merged run absent from the database.

    Rows already present for that device in the target are replaced, so merging
    the same sources twice is not an error and does not double anything. A
    source with no rows for the device, one the database never held, leaves
    the target's as they are: they were read from the files the merge copied,
    and replacing them with nothing loses the device.

    ``device`` is the name the outputs are stored under: the testbed's.
    ``held_in`` is the database the source run is held in, where that is not
    the target's: a merge landing in another estate directory reads its
    sources through the databases beside them, and looked for in the
    target's alone, the rows of a run pruned after ingest were not found.
    """
    rows = (held_in or connection).execute(
        "SELECT * FROM outputs WHERE snapshot_id = ? AND device = ?",
        (source_snapshot, device),
    ).fetchall()
    if not rows:
        return 0
    with connection:
        connection.execute(
            "DELETE FROM outputs WHERE snapshot_id = ? AND device = ?",
            (target_snapshot, device),
        )
        for row in rows:
            connection.execute(
                """
                INSERT OR REPLACE INTO outputs (
                    snapshot_id, device, command, status, detail, seconds,
                    redacted_lines, raw, state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_snapshot, device, row["command"], row["status"],
                    row["detail"], row["seconds"], row["redacted_lines"],
                    row["raw"], row["state"],
                ),
            )
    return len(rows)


class RunInMerge(Exception):
    """A run a merged run the database holds was made from, which :func:`forget` keeps.

    ``merges`` names those merged runs. Forgetting them first frees the run.
    """

    def __init__(self, snapshot_id: str, merges: list[str]) -> None:
        super().__init__(f"{snapshot_id} is a source of {', '.join(merges)}")
        self.snapshot_id = snapshot_id
        self.merges = merges


def merges_of(connection: sqlite3.Connection, snapshot_id: str) -> list[str]:
    """The merged runs held that list this run in their `merged_from`, by id."""
    found: list[str] = []
    for row in connection.execute(
        "SELECT snapshot_id, manifest FROM snapshots WHERE merged = 1 AND snapshot_id != ? "
        "ORDER BY snapshot_id",
        (snapshot_id,),
    ):
        try:
            sources = (json.loads(row["manifest"]) or {}).get("merged_from") or []
        except ValueError:
            continue
        if any(isinstance(source, dict) and str(source.get("snapshot_id")) == snapshot_id for source in sources):
            found.append(row["snapshot_id"])
    return found


def forget(connection: sqlite3.Connection, snapshot_id: str) -> bool:
    """Remove one run from the database. True if there was one to remove.

    The estate inventory forgets it too. Each box it reached is read again
    from the runs left, and a box no run left reaches is dropped: kept as
    they were, the counts went on counting the run, and the seen-dates and
    last snapshot went on naming a run the database no longer holds.

    A run a held merge was made from is not removed: :class:`RunInMerge`
    names the merge. Merged runs are left out of the counts and the
    seen-dates, so once its sources were gone the merge was the only record
    of what they read, and `db estate` said a device whose output the
    database holds had never answered.
    """
    merges = merges_of(connection, snapshot_id) if has_snapshot(connection, snapshot_id) else []
    if merges:
        raise RunInMerge(snapshot_id, merges)
    with connection:
        names = {
            row["name"]
            for row in connection.execute("SELECT name FROM devices WHERE snapshot_id = ?", (snapshot_id,))
        }
        # What the run said about each box, so that what only it said goes
        # with it (_reread).
        said: dict[str, set[str]] = {key: set() for key in ("os", *_FACT_COLUMNS)}
        for row in connection.execute(
            "SELECT os, platform FROM devices WHERE snapshot_id = ?", (snapshot_id,)
        ):
            said["os"].add(row["os"])
            said["platform"].add(row["platform"])
        for row in connection.execute(
            "SELECT * FROM device_facts WHERE snapshot_id = ?", (snapshot_id,)
        ):
            for key in _FACT_COLUMNS:
                said[key].add(row[key])
        cursor = connection.execute(
            "DELETE FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
        )
        for row in _matching_rows(connection, names, None, None) if names else []:
            _reread(connection, row["name"], said)
    return cursor.rowcount > 0


def compact(connection: sqlite3.Connection, path: Path | str) -> tuple[int, int]:
    """Give the space of forgotten runs back to the filesystem: bytes before and after.

    A deleted row leaves its pages inside the file for reuse; the file
    shrinks only when it is rebuilt. Every run holds the redacted text of
    every command on every device, so a database that has forgotten ten runs
    of two hundred devices is most of a gigabyte that a `du` still counts.
    """
    before = Path(path).stat().st_size
    connection.execute("VACUUM")
    after = Path(path).stat().st_size
    return before, after


def has_snapshot(connection: sqlite3.Connection, snapshot_id: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
    ).fetchone()
    return row is not None


def merged_read_by(manifest: dict[str, Any], names: Iterable[str]) -> tuple[str, str]:
    """The run a merge took a device from and when it read it, by any of its names; ("", "") for none.

    The one reading of `device_sources` and `device_read_at` (or, in a merge
    written before the date was recorded per device, of `merged_from`), for
    :meth:`Snapshot.read_by` and for the estate table. A manifest that is not
    a merge's, or does not name the device, gives ("", "").
    """
    names = [name for name in names if name]
    sources = manifest.get("device_sources") or {}
    if not isinstance(sources, dict):
        return "", ""
    source = next((str(sources[name]) for name in names if sources.get(name)), "")
    if not source:
        return "", ""
    dates = manifest.get("device_read_at") or {}
    when = next((str(dates[name]) for name in names if isinstance(dates, dict) and dates.get(name)), "")
    if not when:
        when = next(
            (
                str(run["created_at"])
                for run in manifest.get("merged_from") or []
                if isinstance(run, dict) and run.get("snapshot_id") == source and run.get("created_at")
            ),
            "",
        )
    return source, when


def _stand_ins(connection: sqlite3.Connection, names: list[str]) -> dict[str, tuple[bool, str, str]]:
    """The runs not held that a merged run's row of this box stands in for.

    Keyed by the run that read the box, as `device_sources` names it, each
    with whether it answered, when it read it, and the merged run holding
    the row. Merged runs are left out of the counts and seen-dates because
    the runs they were made from carry their own; a run kept out of the
    database by design — one cut short — carries nothing, and the box it
    reached read as one that never answered although the merge holds its
    output. Two merges of the same read are one run.
    """
    marks = ", ".join("?" for _ in names)
    rows = connection.execute(
        f"""
        SELECT d.name, d.entry, d.produced_data, s.snapshot_id, s.manifest
        FROM devices d JOIN snapshots s USING (snapshot_id)
        WHERE s.merged = 1 AND d.name IN ({marks})
        ORDER BY s.created_at, s.snapshot_id
        """,
        names,
    ).fetchall()
    found: dict[str, tuple[bool, str, str]] = {}
    for row in rows:
        try:
            manifest = json.loads(row["manifest"] or "{}") or {}
            testbed = str(json.loads(row["entry"] or "{}").get("testbed_name") or "")
        except (TypeError, ValueError, AttributeError):
            continue
        source, when = merged_read_by(manifest, (row["name"], testbed))
        if not source or source in found or has_snapshot(connection, source):
            continue
        found[source] = (bool(row["produced_data"]), when, row["snapshot_id"])
    return found


def recorded_root(connection: sqlite3.Connection, snapshot_id: str) -> Path | None:
    """The directory a held run was collected into, as ingest recorded it; None if unrecorded.

    Ingest records the resolved directory. An older one recorded the path
    as it was given, often relative to wherever the collect ran, which is no
    help to a command run from anywhere else. Such a root is read against the
    database's own directory and each directory above it, the first that
    holds it winning: the database lives beside the runs, in the estate the
    path was given from. Found under none, it is returned as recorded.
    """
    row = connection.execute(
        "SELECT root FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
    ).fetchone()
    if row is None or not row["root"]:
        return None
    root = Path(row["root"])
    if root.is_absolute():
        return root
    database = next(
        (str(entry["file"]) for entry in connection.execute("PRAGMA database_list") if entry["name"] == "main"),
        "",
    )
    if database:
        directory = Path(database).resolve().parent
        for anchor in (directory, *directory.parents):
            if (anchor / root).is_dir():
                return anchor / root
    return root


def snapshot_ids(connection: sqlite3.Connection) -> list[str]:
    """Every run held, newest first. Snapshot ids are UTC stamps, so this sorts."""
    return [
        row["snapshot_id"]
        for row in connection.execute(
            "SELECT snapshot_id FROM snapshots ORDER BY created_at DESC, snapshot_id DESC"
        )
    ]


def manifest_of(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT manifest FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
    ).fetchone()
    return json.loads(row["manifest"]) if row else None


def output(
    connection: sqlite3.Connection, snapshot_id: str, device: str, command: str
) -> sqlite3.Row | None:
    """One command's row. The command is matched as stored — normalise first."""
    return connection.execute(
        "SELECT * FROM outputs WHERE snapshot_id = ? AND device = ? AND command = ?",
        (snapshot_id, device, command),
    ).fetchone()


def outputs_for(
    connection: sqlite3.Connection, snapshot_id: str, device: str
) -> list[sqlite3.Row]:
    return list(
        connection.execute(
            "SELECT * FROM outputs WHERE snapshot_id = ? AND device = ?",
            (snapshot_id, device),
        )
    )


# --------------------------------------------------------------------------
# The estate view
# --------------------------------------------------------------------------


def update_estate(
    connection: sqlite3.Connection,
    snapshot_id: str,
    facts: dict[str, dict[str, Any]] | None = None,
) -> int:
    """Fold one run into the standing estate inventory.

    ``facts`` carries anything the caller has learned that the manifest does not
    hold — a management address, the software version, a serial number, the
    hostname the device gave. It is optional because the inventory is still
    useful without it, and because the parts of DiscoNet that know those things
    (topology, finalize) run later than ingest does.

    A row is a box, found by any name it has been reached under, by a chassis
    serial it printed, or by its management address, in that order. A device
    reached as ``dev_10_1_1_1`` on Monday and as ``PE1`` after ``finalize``
    renamed it is one row called ``PE1`` with the placeholder among its aliases.

    First-seen never moves backwards and last-seen never moves back in time, so
    re-ingesting an old run cannot rewrite the estate's history into a lie, nor
    its facts: an older run fills a fact the row lacks and replaces none; the
    run counters are counted, not incremented, so re-ingesting cannot inflate
    them either. Last-seen is the newest run the box answered in, a merged run
    aside: a box that stopped answering does not look current, and a box that
    never answered has not been seen.
    """
    facts = facts or {}
    run = connection.execute(
        "SELECT created_at, merged, manifest FROM snapshots WHERE snapshot_id = ?", (snapshot_id,)
    ).fetchone()
    run_created_at = str(run["created_at"]) if run else ""
    # A merged run's date is when earlier reads were folded together, not
    # when any device was read; the runs it was made from carry their own.
    # One the database does not hold carries nothing, and the merge's row
    # stands in for it, dated by when it read the box (_stand_ins).
    merged = bool(run["merged"]) if run else False
    try:
        run_manifest = (json.loads(run["manifest"] or "{}") or {}) if merged else {}
    except (TypeError, ValueError):
        run_manifest = {}
    touched = 0
    with connection:
        for row in connection.execute(
            "SELECT * FROM devices WHERE snapshot_id = ?", (snapshot_id,)
        ).fetchall():
            name = row["name"]
            # A merged run lists a renamed placeholder by its hostname and keeps
            # the testbed's name beside it, which is what the facts are keyed by
            # and what the runs it was merged from called the box.
            try:
                testbed = str(json.loads(row["entry"] or "{}").get("testbed_name") or "")
            except (TypeError, ValueError, AttributeError):
                testbed = ""
            extra = facts.get(name) or facts.get(testbed) or {}
            hostname = str(extra.get("hostname") or "").strip()
            names = {name} | ({testbed} if testbed else set()) | ({hostname} if hostname else set())
            matches = _matching_rows(
                connection, names, extra.get("serial"), extra.get("mgmt_ip")
            )
            preferred = _preferred_name(names, [m["name"] for m in matches])
            created_at = run_created_at
            stands_in = False
            if merged:
                source, when = merged_read_by(run_manifest, (name, testbed))
                stands_in = bool(source) and not has_snapshot(connection, source)
                if stands_in and when:
                    created_at = when
            seen = bool(row["produced_data"]) and (not merged or stands_in)
            given = {key: extra.get(key) for key in _FACT_COLUMNS}
            if any(given.values()):
                connection.execute(
                    "INSERT OR REPLACE INTO device_facts (snapshot_id, name, mgmt_ip, platform, "
                    "software, serial) VALUES (?, ?, ?, ?, ?, ?)",
                    (snapshot_id, name, *(given[key] for key in _FACT_COLUMNS)),
                )
            if not matches:
                connection.execute(
                    """
                    INSERT INTO estate_devices (
                        name, aliases, mgmt_ip, os, platform, software, serial,
                        first_seen, last_seen, last_snapshot, runs, answered_runs
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
                    """,
                    (
                        preferred,
                        json.dumps(sorted(names - {preferred})),
                        extra.get("mgmt_ip"),
                        row["os"] or extra.get("os"),
                        row["platform"] or extra.get("platform"),
                        extra.get("software"),
                        extra.get("serial"),
                        created_at,
                        created_at if seen else None,
                        snapshot_id if seen else None,
                    ),
                )
            else:
                existing = _fold(connection, matches, preferred, names)
                newer = created_at >= (existing["last_seen"] or "")
                # COALESCE because SQLite's MAX of anything and NULL is NULL,
                # and a box that has never answered has no last-seen yet.
                # The address, software and serial a newer run gives replace
                # the row's; an older one's only fill a gap. Taken from any
                # run, `db import` of an archived March run put March's
                # software and serial on a box September had read, and the
                # same newest-wins rule is what forget reads them again by.
                connection.execute(
                    """
                    UPDATE estate_devices SET
                        mgmt_ip       = CASE WHEN ? THEN COALESCE(?, mgmt_ip) ELSE COALESCE(mgmt_ip, ?) END,
                        os            = COALESCE(?, os),
                        platform      = COALESCE(?, platform),
                        software      = CASE WHEN ? THEN COALESCE(?, software) ELSE COALESCE(software, ?) END,
                        serial        = CASE WHEN ? THEN COALESCE(?, serial) ELSE COALESCE(serial, ?) END,
                        first_seen    = MIN(first_seen, ?),
                        last_seen     = CASE WHEN ? THEN MAX(COALESCE(last_seen, ''), ?)
                                        ELSE last_seen END,
                        last_snapshot = CASE WHEN ? THEN ? ELSE last_snapshot END
                    WHERE name = ?
                    """,
                    (
                        1 if newer else 0, extra.get("mgmt_ip"), extra.get("mgmt_ip"),
                        row["os"] if newer else None,
                        row["platform"] if newer else None,
                        1 if newer else 0, extra.get("software"), extra.get("software"),
                        1 if newer else 0, extra.get("serial"), extra.get("serial"),
                        created_at or existing["first_seen"],
                        1 if seen and created_at else 0,
                        created_at,
                        1 if seen and newer else 0,
                        snapshot_id,
                        preferred,
                    ),
                )
            _recount(connection, preferred)
            touched += 1
    return touched


def _aliases(row: sqlite3.Row) -> set[str]:
    try:
        stored = json.loads(row["aliases"] or "[]")
    except (TypeError, ValueError):
        stored = []
    return {str(alias) for alias in stored if alias}


def _serials(value: Any) -> set[str]:
    return {part.strip() for part in str(value or "").split(",") if part.strip()}


def _matching_rows(
    connection: sqlite3.Connection,
    names: set[str],
    serial: Any,
    mgmt_ip: Any,
) -> list[sqlite3.Row]:
    """Every estate row that is this box: by name or alias, serial, or address."""
    serials = _serials(serial)
    address = str(mgmt_ip or "").strip()
    found: dict[str, sqlite3.Row] = {}
    for row in connection.execute("SELECT * FROM estate_devices").fetchall():
        if row["name"] in names or (_aliases(row) & names):
            found[row["name"]] = row
        elif serials and (_serials(row["serial"]) & serials):
            found[row["name"]] = row
        elif address and str(row["mgmt_ip"] or "").strip() == address:
            found[row["name"]] = row
    return sorted(found.values(), key=lambda r: (r["last_seen"] or "", r["name"]), reverse=True)


def _preferred_name(names: set[str], existing: list[str]) -> str:
    """The name a box's row wears: a hostname over a placeholder, the newest otherwise.

    ``existing`` is newest-first. A row already called by a hostname keeps it;
    a run that learned the hostname of a placeholder renames the row.
    """
    real_existing = [name for name in existing if not _PLACEHOLDER.match(name)]
    if real_existing:
        return real_existing[0]
    real_new = sorted(name for name in names if not _PLACEHOLDER.match(name))
    if real_new:
        return real_new[0]
    return existing[0] if existing else sorted(names)[0]


def _fold(
    connection: sqlite3.Connection,
    rows: list[sqlite3.Row],
    preferred: str,
    names: set[str] = frozenset(),
) -> sqlite3.Row:
    """Make one row of several that are the same box, called ``preferred``.

    Facts come from the newest row that has them, the seen-dates bracket every
    row, and every other name becomes an alias. Returns the surviving row.
    """
    aliases: set[str] = set(names)
    for row in rows:
        aliases |= {row["name"]} | _aliases(row)
    aliases.discard(preferred)
    newest = rows[0]
    keep = next((row for row in rows if row["name"] == preferred), newest)
    first_seen = min((row["first_seen"] for row in rows if row["first_seen"]), default=None)
    last_seen = max((row["last_seen"] for row in rows if row["last_seen"]), default=None)

    def first(column: str) -> Any:
        return next((row[column] for row in rows if row[column]), None)

    for row in rows:
        if row["name"] != keep["name"]:
            connection.execute("DELETE FROM estate_devices WHERE name = ?", (row["name"],))
    connection.execute(
        """
        UPDATE estate_devices SET
            name = ?, aliases = ?, mgmt_ip = ?, os = ?, platform = ?, software = ?,
            serial = ?, first_seen = ?, last_seen = ?, last_snapshot = ?
        WHERE name = ?
        """,
        (
            preferred,
            json.dumps(sorted(aliases)),
            first("mgmt_ip"),
            first("os"),
            first("platform"),
            first("software"),
            first("serial"),
            first_seen,
            last_seen,
            newest["last_snapshot"],
            keep["name"],
        ),
    )
    return connection.execute(
        "SELECT * FROM estate_devices WHERE name = ?", (preferred,)
    ).fetchone()


def _recount(connection: sqlite3.Connection, name: str) -> None:
    """Count the runs that reached this box, under any of its names, leaving merged runs out.

    Runs, not rows: one run can reach a box under two names (a router swept
    at two of its addresses), and that is still one run, answered once if
    either answered. A run not held that a merge took the box from is
    counted through the merge (:func:`_stand_ins`).
    """
    row = connection.execute(
        "SELECT * FROM estate_devices WHERE name = ?", (name,)
    ).fetchone()
    if row is None:
        return
    names = sorted({name} | _aliases(row))
    marks = ", ".join("?" for _ in names)
    stand_ins = _stand_ins(connection, names)
    counted = connection.execute(
        f"""
        SELECT COUNT(DISTINCT d.snapshot_id) AS runs,
               COUNT(DISTINCT CASE WHEN d.produced_data THEN d.snapshot_id END) AS answered
        FROM devices d JOIN snapshots s USING (snapshot_id)
        WHERE s.merged = 0 AND d.name IN ({marks})
        """,
        names,
    ).fetchone()
    connection.execute(
        "UPDATE estate_devices SET runs = ?, answered_runs = ? WHERE name = ?",
        (
            int(counted["runs"]) + len(stand_ins),
            int(counted["answered"]) + sum(1 for answered, _when, _run in stand_ins.values() if answered),
            name,
        ),
    )


def _reread(
    connection: sqlite3.Connection, name: str, said: dict[str, set[str]] | None = None
) -> None:
    """Read a box's row again from the runs held, or drop it when none holds it.

    The same rules :func:`update_estate` keeps as runs arrive: first seen is
    the first run that reached the box, last seen the newest it answered in,
    a merged run aside. ``said`` is what the forgotten run said about it,
    for :func:`_refact`.
    """
    row = connection.execute(
        "SELECT * FROM estate_devices WHERE name = ?", (name,)
    ).fetchone()
    if row is None:
        return
    names = sorted({name} | _aliases(row))
    marks = ", ".join("?" for _ in names)
    held = connection.execute(
        f"""
        SELECT COUNT(*) AS runs, MIN(NULLIF(s.created_at, '')) AS first_seen
        FROM devices d JOIN snapshots s USING (snapshot_id)
        WHERE d.name IN ({marks})
        """,
        names,
    ).fetchone()
    if not held["runs"]:
        connection.execute("DELETE FROM estate_devices WHERE name = ?", (name,))
        return
    last = connection.execute(
        f"""
        SELECT s.created_at, s.snapshot_id
        FROM devices d JOIN snapshots s USING (snapshot_id)
        WHERE d.name IN ({marks}) AND d.produced_data = 1 AND s.merged = 0 AND s.created_at != ''
        ORDER BY s.created_at DESC, s.snapshot_id DESC LIMIT 1
        """,
        names,
    ).fetchone()
    seen = (str(last["created_at"]), str(last["snapshot_id"])) if last else None
    first_seen = held["first_seen"]
    # A read by a run not held is seen through the merge that holds it,
    # as update_estate saw it.
    for answered, when, merged_run in _stand_ins(connection, names).values():
        if when and (first_seen is None or when < first_seen):
            first_seen = when
        if answered and when and (seen is None or when > seen[0]):
            seen = (when, merged_run)
    connection.execute(
        "UPDATE estate_devices SET first_seen = ?, last_seen = ?, last_snapshot = ? WHERE name = ?",
        (
            first_seen,
            seen[0] if seen else None,
            seen[1] if seen else None,
            name,
        ),
    )
    if said is not None:
        _refact(connection, name, names, said)
    _recount(connection, name)


# The estate columns read from what update_estate is told, rather than from
# the manifest, and kept per run in device_facts.
_FACT_COLUMNS = ("mgmt_ip", "platform", "software", "serial")


def _refact(
    connection: sqlite3.Connection, name: str, names: list[str], said: dict[str, set[str]]
) -> None:
    """Read a box's facts again from the runs held, after one was forgotten.

    Each column takes the newest value a held run gave: `os` and `platform`
    from the manifests, `platform` failing that and the rest from what each
    run told update_estate. A column no held run gives keeps its value,
    unless it is what the forgotten run said — then it is the forgotten
    run's, and goes. A run stored before device_facts existed gave nothing
    to read again, so what the row holds from it stays.
    """
    marks = ", ".join("?" for _ in names)
    newest: dict[str, Any] = {}
    for row in connection.execute(
        f"""
        SELECT d.os, d.platform FROM devices d JOIN snapshots s USING (snapshot_id)
        WHERE d.name IN ({marks}) ORDER BY s.created_at, s.snapshot_id
        """,
        names,
    ):
        for key in ("os", "platform"):
            if row[key]:
                newest[key] = row[key]
    told: dict[str, Any] = {}
    for row in connection.execute(
        f"""
        SELECT f.* FROM device_facts f JOIN snapshots s USING (snapshot_id)
        WHERE f.name IN ({marks}) ORDER BY s.created_at, s.snapshot_id
        """,
        names,
    ):
        for key in _FACT_COLUMNS:
            if row[key]:
                told[key] = row[key]
    for key, value in told.items():
        newest.setdefault(key, value)
    current = connection.execute("SELECT * FROM estate_devices WHERE name = ?", (name,)).fetchone()
    for key in ("os", *_FACT_COLUMNS):
        if key in newest:
            value = newest[key]
        elif current[key] in said.get(key, set()):
            value = None
        else:
            continue
        connection.execute(f"UPDATE estate_devices SET {key} = ? WHERE name = ?", (value, name))


def _fold_duplicates(connection: sqlite3.Connection) -> None:
    """Merge rows an older schema split: one box under two names.

    Rows that share a chassis serial or a management address are one box. The
    surviving name is a hostname over a placeholder, the newest otherwise.
    """
    rows = connection.execute("SELECT * FROM estate_devices").fetchall()
    parent = {row["name"]: row["name"] for row in rows}

    def find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    by_serial: dict[str, str] = {}
    by_address: dict[str, str] = {}
    for row in rows:
        for serial in _serials(row["serial"]):
            if serial in by_serial:
                parent[find(row["name"])] = find(by_serial[serial])
            else:
                by_serial[serial] = row["name"]
        address = str(row["mgmt_ip"] or "").strip()
        if address:
            if address in by_address:
                parent[find(row["name"])] = find(by_address[address])
            else:
                by_address[address] = row["name"]
    groups: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        groups.setdefault(find(row["name"]), []).append(row)
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort(key=lambda r: (r["last_seen"] or "", r["name"]), reverse=True)
        preferred = _preferred_name(set(), [m["name"] for m in members])
        _fold(connection, members, preferred)


def estate(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(connection.execute("SELECT * FROM estate_devices ORDER BY name"))


# --------------------------------------------------------------------------
# Queries the database exists for
# --------------------------------------------------------------------------


def command_history(
    connection: sqlite3.Connection, device: str, command: str
) -> list[dict[str, Any]]:
    """How one command has turned out on one device, over every run held.

    The query the directory layout could not answer, and the reason for keeping
    one database per estate rather than one per run.

    ``device`` is the box, by any name the estate table knows it under: its
    outputs are stored under the name each run's testbed gave it, and after
    finalize renamed a placeholder the runs before the rename were found
    only under the placeholder, while `db estate` listed the box by its
    hostname with every run counted.

    A merged run's row is a copy of a read some other run made, and dated by
    the merge it was listed as a second read on a day the box may not have
    been collected at all. It is left out, as the estate's counts leave it
    out, unless the run that read the box is not held — one cut short, kept
    out by design — and then it is listed once, as that run's, dated by
    when it read the box (:func:`_stand_ins`).
    """
    names = {device}
    for row in _matching_rows(connection, {device}, None, None):
        names |= {row["name"]} | _aliases(row)
    marks = ", ".join("?" for _ in names)
    history: list[dict[str, Any]] = []
    stood_in: set[str] = set()
    for row in connection.execute(
        f"""
        SELECT o.snapshot_id, s.created_at, o.status, o.detail, o.seconds, o.device, s.merged, s.manifest
        FROM outputs o JOIN snapshots s USING (snapshot_id)
        WHERE o.device IN ({marks}) AND o.command = ?
        ORDER BY s.created_at, s.snapshot_id
        """,
        (*sorted(names), command),
    ):
        read = {key: row[key] for key in ("snapshot_id", "created_at", "status", "detail", "seconds")}
        if row["merged"]:
            try:
                manifest = json.loads(row["manifest"] or "{}") or {}
            except (TypeError, ValueError):
                continue
            source, when = merged_read_by(manifest, (row["device"], *sorted(names)))
            if not source or source in stood_in or has_snapshot(connection, source):
                continue
            stood_in.add(source)
            read.update(snapshot_id=source, created_at=when or row["created_at"])
        history.append(read)
    return sorted(history, key=lambda read: (str(read["created_at"] or ""), str(read["snapshot_id"])))


def unreachable_history(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every device that failed to answer, and in which run."""
    return list(
        connection.execute(
            """
            SELECT d.snapshot_id, s.created_at, d.name, d.error
            FROM devices d JOIN snapshots s USING (snapshot_id)
            WHERE d.produced_data = 0
            ORDER BY s.created_at DESC, d.name
            """
        )
    )


def compare_status(
    connection: sqlite3.Connection, older: str, newer: str
) -> list[dict[str, Any]]:
    """Commands whose outcome changed between two runs.

    A command that parsed in March and is unparsed today is either a software
    upgrade or a broken parser, and both are worth knowing before the document
    quietly loses a section.

    A device is matched across the runs as the box the estate table says it
    is, so a placeholder finalize renamed is compared with itself. A command
    one run has and the other has not — a device that stopped answering, a
    command the allowlist dropped — is a change, with None for the side that
    has no outcome, not a row the comparison leaves out.
    """
    boxes = _boxes(connection)

    def outcomes(snapshot_id: str) -> dict[tuple[str, str], Any]:
        names = _run_boxes(connection, snapshot_id, boxes)
        return {
            (names.get(row["device"]) or boxes.get(row["device"], row["device"]), row["command"]):
                row["status"]
            for row in connection.execute(
                "SELECT device, command, status FROM outputs WHERE snapshot_id = ?",
                (snapshot_id,),
            )
        }

    was, now = outcomes(older), outcomes(newer)
    changed: list[dict[str, Any]] = []
    for device, command in sorted(set(was) | set(now)):
        key = (device, command)
        if key in was and key in now and (was[key] or "") == (now[key] or ""):
            continue
        changed.append({"device": device, "command": command, "was": was.get(key), "now": now.get(key)})
    return changed


def compare_devices(
    connection: sqlite3.Connection, older: str, newer: str
) -> list[dict[str, Any]]:
    """Devices whose answer, or the name a run reached them under, changed between two runs.

    The command comparison has nothing to say about a device that answered
    nothing, and that is the change most worth seeing. Each side reads
    "answered", "did not answer" or "not in the run", with the name the run
    used where it is not the box's own.
    """
    boxes = _boxes(connection)

    def reads(snapshot_id: str) -> dict[str, str]:
        names = _run_boxes(connection, snapshot_id, boxes)
        found: dict[str, str] = {}
        for row in connection.execute(
            "SELECT name, produced_data FROM devices WHERE snapshot_id = ?", (snapshot_id,)
        ):
            box = names[row["name"]]
            read = "answered" if row["produced_data"] else "did not answer"
            found[box] = read if row["name"] == box else f"{read} as {row['name']}"
        return found

    was, now = reads(older), reads(newer)
    absent = "not in the run"
    return [
        {"device": box, "was": was.get(box, absent), "now": now.get(box, absent)}
        for box in sorted(set(was) | set(now))
        if was.get(box) != now.get(box)
    ]


def _boxes(connection: sqlite3.Connection) -> dict[str, str]:
    """Every name the estate table knows a box by, to the name its row wears."""
    found: dict[str, str] = {}
    for row in connection.execute("SELECT name, aliases FROM estate_devices"):
        found[row["name"]] = row["name"]
        for alias in _aliases(row):
            found.setdefault(alias, row["name"])
    return found


def _run_boxes(
    connection: sqlite3.Connection, snapshot_id: str, boxes: dict[str, str]
) -> dict[str, str]:
    """A run's device names, and the testbed names its outputs are stored under, to boxes.

    A merged run calls a device by its hostname and stores its outputs under
    the placeholder; either name the estate table knows decides the box.
    """
    found: dict[str, str] = {}
    for row in connection.execute(
        "SELECT name, entry FROM devices WHERE snapshot_id = ?", (snapshot_id,)
    ):
        try:
            entry = json.loads(row["entry"] or "{}")
        except (TypeError, ValueError):
            entry = {}
        testbed = str(entry.get("testbed_name") or row["name"])
        box = boxes.get(row["name"]) or boxes.get(testbed) or row["name"]
        found[row["name"]] = found[testbed] = box
    return found


def counts(connection: sqlite3.Connection) -> dict[str, int]:
    """Row counts, for the summary line after an ingest."""
    return {
        table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("snapshots", "devices", "outputs", "estate_devices")
    }


def iter_snapshot_dirs(base_dir: Path | str) -> Iterator[Path]:
    """Snapshot directories under a base directory, oldest first."""
    base = Path(base_dir)
    if not base.is_dir():
        return
    for child in sorted(base.iterdir()):
        if child.is_dir() and (child / "manifest.json").is_file():
            yield child


def cut_short(manifest: dict[str, Any]) -> str:
    """Why the run stopped before its end, as its manifest says; "" for a run that reached it.

    `collect` marks the manifest of a run it could not finish `interrupted`.
    A merge keeps the mark of a source cut short, so its gap list can name
    what no run finished; the merge itself was not cut short, and is often
    the very run that filled that one in.
    """
    interrupted = manifest.get("interrupted")
    if not interrupted or manifest.get("merged_from"):
        return ""
    reason = interrupted.get("reason") if isinstance(interrupted, dict) else ""
    return str(reason or "interrupted")


def backfill(
    connection: sqlite3.Connection,
    base_dir: Path | str,
    facts: Callable[[Path], dict[str, dict[str, Any]]] | None = None,
    include_partial: bool = False,
    passed_over: Callable[[Path, str], None] | None = None,
) -> list[str]:
    """Ingest every snapshot directory that is not in the database yet.

    The migration path for an estate that already has months of runs on disk:
    the directories are the record, this makes them queryable, and nothing is
    deleted in the process.

    ``facts`` reads a run directory for what :func:`update_estate` keeps that
    the manifest does not: the hostname, the serials, the software. It is the
    collector's to give, since this module reads no device output itself.
    Folded without them, a placeholder finalize renamed was a row under each
    name, and no row carried a serial to join a box reached by a new name.

    A run cut short (:func:`cut_short`) is left out, as `collect` left it
    out, unless ``include_partial``: held, it would be the estate's newest
    run, of only the devices that finished. ``passed_over`` is told of each
    one left out, and why it stopped.
    """
    ingested: list[str] = []
    for directory in iter_snapshot_dirs(base_dir):
        try:
            snapshot_id = snapshot_id_of(directory)
            if has_snapshot(connection, snapshot_id):
                continue
            manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
            reason = cut_short(manifest)
            if reason and not include_partial:
                if passed_over is not None:
                    passed_over(directory, reason)
                continue
            ingest(connection, directory, manifest)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("skipped %s: %s", directory, exc)
            continue
        update_estate(connection, snapshot_id, facts=facts(directory) if facts else None)
        ingested.append(snapshot_id)
    return ingested


def snapshot_id_of(snapshot_root: Path | str) -> str:
    """The id a snapshot directory is stored under: the manifest's, not the directory's.

    A run copied to ``snapshots/before-upgrade`` is still the run it was, so
    ``db import`` finds it already present instead of storing it twice and
    pointing the original's ``root`` at the copy.
    """
    snapshot_root = Path(snapshot_root)
    manifest = json.loads((snapshot_root / "manifest.json").read_text(encoding="utf-8"))
    return str(manifest.get("snapshot_id") or snapshot_root.name)


# Files the raw text and parsed state live in before ingest. Pruning them is
# opt-in: the database holds everything they do, but a directory of text is
# still what a colleague greps at three in the morning, and that is worth more
# than the disk it costs until someone decides otherwise.
PRUNABLE = ("raw", "state")


def unheld_files(
    connection: sqlite3.Connection, snapshot_root: Path | str, manifest: dict[str, Any]
) -> list[str]:
    """The per-command files on disk whose text the database does not hold.

    Ingest stores a file it cannot read (not UTF-8, or not the user's to
    read) as nothing, which is right for the database and wrong for pruning:
    that file is then the only copy of what the device said. A file the
    manifest names and the run never wrote has nothing to lose.
    """
    snapshot_root = Path(snapshot_root)
    snapshot_id = str(manifest.get("snapshot_id") or snapshot_root.name)
    unheld: list[str] = []
    for name, entry in (manifest.get("devices") or {}).items():
        stored = str(entry.get("testbed_name") or name)
        for command in entry.get("commands") or []:
            row = output(connection, snapshot_id, stored, str(command.get("command", "")))
            for key, column in (("raw_file", "raw"), ("state_file", "state")):
                relative = command.get(key)
                if not relative or not (snapshot_root / relative).is_file():
                    continue
                if row is None or row[column] is None:
                    unheld.append(str(relative))
    return unheld


def prune_files(snapshot_root: Path | str) -> int:
    """Delete the per-command text files, keeping the rest of the snapshot.

    Only ever called after a successful ingest, and only for a run whose
    every file the database holds (:func:`unheld_files`). `manifest.json`,
    `collect.log`, `session.log` and every generated artefact stay: they are
    the run's own record, not a duplicate of the database.
    """
    import shutil

    snapshot_root = Path(snapshot_root)
    removed = 0
    for device_dir in snapshot_root.iterdir():
        if not device_dir.is_dir():
            continue
        for name in PRUNABLE:
            target = device_dir / name
            if target.is_dir():
                removed += sum(1 for _ in target.rglob("*") if _.is_file())
                shutil.rmtree(target)
    return removed


def files_pruned(snapshot_root: Path | str, manifest: dict[str, Any] | None = None) -> bool:
    """Has this run lost every per-command file its manifest names, as pruning does?

    A pruned run's database is the only copy of what the devices said. One
    file missing is a damaged run, not a pruned one, and a run that answered
    nothing named no files to lose. Pruning takes each device's raw/ and
    state/ and leaves the device directory, so a manifest with none of its
    directories beside it is not this case either.
    """
    snapshot_root = Path(snapshot_root)
    if manifest is None:
        try:
            manifest = json.loads((snapshot_root / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
    named = [
        str(command[key])
        for entry in (manifest.get("devices") or {}).values()
        for command in entry.get("commands") or []
        for key in ("raw_file", "state_file")
        if command.get(key)
    ]
    if not named or any((snapshot_root / name).is_file() for name in named):
        return False
    return all((snapshot_root / Path(name).parts[0]).is_dir() for name in named)
