"""WS3: `disconet export` and `verify`, one archive a prospect sends and the owner can trust.

The fixture is an estate written by hand in a temporary directory: a snapshot
of three demo devices (iosxr, junos, iosxe) whose manifest names its raw and
state files, a testbed holding every kind of credential a hand-written one
can, and decoys a careless export would carry: generated outputs beside the
snapshot, the estate database, lifecycle.yaml, docmeta.yaml, .env, the run's
logs, a device's connect.log and a file in raw/ the manifest does not name.

The tests say what must hold of the archive (exactly the collection, no
secret, the same bytes twice) and that `verify` fails every way an archive
can be altered after it was written: a file changed, removed or added, the
allowlist hash, the signature, the summary, a member that is a generated
output, the database, a link or a path out of the folder. A merged snapshot
is described run by run (each run's collector, finish and allowlist hash),
and verify reports whatever an archive holds rather than raising on it. The
testbed's redaction has its own tests, in test_collector_export_testbed.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
from contextlib import redirect_stdout
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from unittest import mock

import yaml

from netstate import cli
from netstate import collector, export, signing, store
from netstate.collector import REDACTION_MARKER

REPO = Path(__file__).resolve().parents[1]

SNAPSHOT_ID = "20261026T101500Z"
EXPORTED_AT = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
ALLOWLIST_SHA256 = hashlib.sha256(collector.DEFAULT_COMMANDS_FILE.read_bytes()).hexdigest()

# Every literal secret the fixture holds, in the testbed and in the decoys.
# None may appear in any member of an archive.
LITERAL_PASSWORD = "Fixture-Pass-4821"
ENCODED_PASSWORD = "%ENC{gAAAAABfixtureEncodedValue}"
JUMP_PASSWORD = "Jump-Pass-7731"
ENABLE_SECRET = "Enable-Secret-9902"
PROMPT_ANSWER = "Prompt-Answer-5510"
COMMUNITY = "Community-Str-3307"
COMMENT_PASSWORD = "Comment-Pass-1188"
ENV_FILE_PASSWORD = "Env-Pass-6604"
SECRETS = (
    LITERAL_PASSWORD, ENCODED_PASSWORD, "gAAAAABfixtureEncodedValue", JUMP_PASSWORD, ENABLE_SECRET,
    PROMPT_ANSWER, COMMUNITY, COMMENT_PASSWORD, ENV_FILE_PASSWORD,
)
# Written into every decoy; never in an archive.
DECOY = "DECOY-NEVER-EXPORTED"

TESTBED = f"""\
# A hand-written testbed, as a prospect may keep one. The jump host's old
# password was {COMMENT_PASSWORD}, kept here as people do.
testbed:
  name: fixture
  credentials:
    default:
      username: netops
      password: {LITERAL_PASSWORD}
    enable:
      password: "{ENCODED_PASSWORD}"
  servers:
    jump:
      address: 192.0.2.50
      credentials:
        default:
          username: jumpuser
          password: {JUMP_PASSWORD}
devices:
  rbt-ald-pe1:
    os: iosxr
    type: router
    platform: ASR-9901
    credentials:
      default:
        username: "%ENV{{DISCONET_USERNAME}}"
        password: "%ENV{{DISCONET_PASSWORD}}"
      enable:
        secret: {ENABLE_SECRET}
    connections:
      cli:
        protocol: ssh
        ip: 192.0.2.11
    custom:
      login_prompts:
        - pattern: "One-time code:"
          response: {PROMPT_ANSWER}
  rbt-bht-p2:
    os: junos
    type: router
    platform: MX204
    credentials:
      default:
        username: netops
        password: "%ASK{{}}"
    connections:
      cli:
        protocol: ssh
        ip: 198.51.100.12
    custom:
      snmp_community: {COMMUNITY}
  rbt-bht-rr2:
    os: iosxe
    type: router
    platform: C8000V
    connections:
      cli:
        protocol: ssh
        ip: 203.0.113.13
        # A jump host's command line that repeats the password in passing.
        command: "ssh -J jumpuser@192.0.2.50 rbt-bht-rr2 # {JUMP_PASSWORD}"
"""
# Five under secrets' keys, the %ENC one, the login answer, and the command
# line that repeats a password; the %ENV and %ASK references are kept.
REDACTED_VALUES = 7

RAW = {
    "rbt-ald-pe1": {
        "show version": (
            "Cisco IOS XR Software, Version 7.9.2\n"
            "rbt-ald-pe1 uptime is 12 weeks, 3 days\n"
            "cisco ASR-9901 () processor with 32G bytes of memory.\n",
            {"software_version": "7.9.2", "device_family": "ASR9K"},
        ),
        "show running-config": (
            "hostname rbt-ald-pe1\n"
            "username netops\n"
            f" secret 10 {REDACTION_MARKER}\n"
            "interface Loopback0\n"
            " ipv4 address 192.0.2.1 255.255.255.255\n",
            None,
        ),
        "show isis adjacency": (
            "IS-IS core Level-2 adjacencies:\n"
            "System Id      Interface        SNPA           State Hold Changed  NSF IPv4 BFD\n"
            "rbt-bht-p2     Hu0/0/0/0        *PtoP*         Up    27   12w3d    Yes Up   Up\n",
            {"isis": {"core": {"level": {"2": {"rbt-bht-p2": {"state": "Up"}}}}}},
        ),
    },
    "rbt-bht-p2": {
        "show version": (
            "Hostname: rbt-bht-p2\nModel: mx204\nJunos: 23.4R1.10\n",
            {"software-information": {"host-name": "rbt-bht-p2", "product-model": "mx204"}},
        ),
        "show configuration": (
            "set system host-name rbt-bht-p2\n"
            "set interfaces lo0 unit 0 family inet address 198.51.100.2/32\n",
            None,
        ),
    },
    "rbt-bht-rr2": {
        "show version": (
            "Cisco IOS XE Software, Version 17.12.03\nrbt-bht-rr2 uptime is 5 weeks\n",
            {"version": {"version": "17.12.03", "hostname": "rbt-bht-rr2"}},
        ),
    },
}
PLATFORMS = {"rbt-ald-pe1": ("iosxr", "ASR-9901"), "rbt-bht-p2": ("junos", "MX204"), "rbt-bht-rr2": ("iosxe", "C8000V")}


def _slug(command: str) -> str:
    return collector.slugify(command)


def build_estate(base: Path, **manifest_changes) -> tuple[Path, Path]:
    """Write the fixture estate under ``base``; returns (estate root, snapshot root)."""
    estate = base / "fixture"
    snapshots = estate / "snapshots"
    root = snapshots / SNAPSHOT_ID
    root.mkdir(parents=True)
    (estate / "testbed.yaml").write_text(TESTBED, encoding="utf-8")

    devices = {}
    for name, commands in RAW.items():
        entries = []
        for command, (text, state) in commands.items():
            raw = f"{name}/raw/{_slug(command)}.txt"
            (root / raw).parent.mkdir(parents=True, exist_ok=True)
            (root / raw).write_text(text, encoding="utf-8")
            entry = {"command": command, "status": "raw" if state is None else "parsed", "raw_file": raw,
                     "state_file": None, "redacted_lines": 0, "seconds": 1.2, "detail": None}
            if state is not None:
                entry["state_file"] = f"{name}/state/{_slug(command)}.json"
                (root / entry["state_file"]).parent.mkdir(parents=True, exist_ok=True)
                (root / entry["state_file"]).write_text(json.dumps(state, indent=2), encoding="utf-8")
            entries.append(entry)
        os_name, platform = PLATFORMS[name]
        devices[name] = {"name": name, "os": os_name, "platform": platform, "connected": True,
                         "detected_os": None, "error": None, "probed": False, "connect_log": None,
                         "commands": entries}
    # A command that failed wrote no file, and names none.
    devices["rbt-bht-rr2"]["commands"].append(
        {"command": "show inventory", "status": "failed", "raw_file": None, "state_file": None,
         "redacted_lines": 0, "seconds": 0.4, "detail": "timed out"})
    # The manifest names the device's connect log; an export never carries it.
    devices["rbt-ald-pe1"]["connect_log"] = "rbt-ald-pe1/connect.log"

    manifest = {
        "netstate_version": "0.2.0",
        "snapshot_id": SNAPSHOT_ID,
        "created_at": "2026-10-26T10:15:00+00:00",
        "finished_at": "2026-10-26T10:21:30.250000+00:00",
        "utc_offset_minutes": 0,
        "testbed": str(estate / "testbed.yaml"),
        "commands_file": str(collector.DEFAULT_COMMANDS_FILE),
        "commands_sha256": ALLOWLIST_SHA256,
        "requested_devices": list(RAW),
        "features": ["isis", "bgp"],
        "features_skipped": ["ospf", "srte"],
        "mode": "loose",
        "estate": "fixture",
        "retry_of": "",
        "devices_not_requested": [],
        "devices": devices,
        "summary": collector.summarise_devices(devices),
    }
    manifest.update(manifest_changes)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # The decoys. Each would be a leak if it reached an archive.
    for name in ("discovered-network.html", "discovered-network.docx", "tables.xlsx", "topology.drawio",
                 "topology.svg", "topology.png", "document.json", "collect.log", "session.log"):
        (root / name).write_text(f"{DECOY} {name}\n", encoding="utf-8")
    for name in ("community/index.html", "community/report.docx", "sections/01-overview.md"):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(f"{DECOY} {name}\n", encoding="utf-8")
    (root / "rbt-ald-pe1" / "connect.log").write_text(f"{DECOY} password: {LITERAL_PASSWORD}\n", encoding="utf-8")
    (root / "rbt-ald-pe1" / "raw" / "show_clock.txt").write_text(f"{DECOY} unnamed\n", encoding="utf-8")
    for name in ("disconet.db", "disconet.db-wal"):
        (snapshots / name).write_text(f"{DECOY} {name}\n", encoding="utf-8")
    (estate / "lifecycle.yaml").write_text(f"# {DECOY}\n", encoding="utf-8")
    (estate / "docmeta.yaml").write_text(f"# {DECOY}\n", encoding="utf-8")
    (estate / ".env").write_text(f"# {DECOY}\nDISCONET_PASSWORD={ENV_FILE_PASSWORD}\n", encoding="utf-8")
    return estate, root


def expected_members() -> set[str]:
    names = {f"{SNAPSHOT_ID}/{name}" for name in ("manifest.json", "testbed.yaml", "export-manifest.json")}
    for name, commands in RAW.items():
        for command, (_text, state) in commands.items():
            names.add(f"{SNAPSHOT_ID}/{name}/raw/{_slug(command)}.txt")
            if state is not None:
                names.add(f"{SNAPSHOT_ID}/{name}/state/{_slug(command)}.json")
    return names


def read_archive(path: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    with tarfile.open(path, "r:gz") as tar:
        return [
            (info, tar.extractfile(info).read() if info.isreg() else None)  # type: ignore[union-attr]
            for info in tar.getmembers()
        ]


def contents(path: Path) -> dict[str, bytes]:
    return {info.name: data for info, data in read_archive(path) if data is not None}


def write_archive(path: Path, entries: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
    """A hand-built archive: each entry as given, a regular file's size set from its bytes."""
    with tarfile.open(path, "w:gz") as tar:
        for info, data in entries:
            info = copy.copy(info)
            if data is None:
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))


def regular(name: str, data: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    return info, data


def listed(document: dict, name: str, data: bytes) -> None:
    """Put ``name`` in the export manifest's file list with its true hash."""
    document["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def rebuild(source: Path, target: Path, change: Callable[[dict[str, bytes], dict], None]) -> None:
    """Rewrite an archive with ``change`` applied to its members and its parsed export manifest.

    The export manifest is written back from the dict ``change`` was given,
    so a test changes the summary, the file list or a member's bytes and
    leaves the rest as export wrote it.
    """
    members = contents(source)
    manifest_name = f"{SNAPSHOT_ID}/export-manifest.json"
    document = json.loads(members[manifest_name])
    change(members, document)
    if manifest_name in members:
        members[manifest_name] = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
    write_archive(target, [regular(name, data) for name, data in members.items()])


class ExportFixture(unittest.TestCase):
    """A fresh fixture estate per test, an output folder beside it, and HOME pointed into the temporary tree."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.estate, self.snapshot = build_estate(self.base)
        self.testbed = self.estate / "testbed.yaml"
        self.out = self.base / "out"
        self.out.mkdir()
        self.home = self.base / "home"
        self.home.mkdir()
        environment = mock.patch.dict(os.environ, {"HOME": str(self.home), "DISCONET_ESTATE": ""})
        environment.start()
        self.addCleanup(environment.stop)

    def exported(self, name: str = "fixture.export.tar.gz", **options) -> export.ExportResult:
        options.setdefault("testbed", self.testbed)
        options.setdefault("exported_at", EXPORTED_AT)
        return export.export_snapshot(self.snapshot, output=self.out / name, **options)

    def rewrite_manifest(self, change: Callable[[dict], None]) -> None:
        path = self.snapshot / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        change(manifest)
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def assert_fails(self, report: export.VerifyReport, *words: str) -> None:
        self.assertFalse(report.ok, "\n".join(report.problems))
        self.assertTrue(report.readable)
        joined = "\n".join(report.problems)
        for word in words:
            self.assertIn(word, joined)


class TheRoundTripHoldsExactlyTheCollection(ExportFixture):
    def test_export_then_verify_is_ok_with_exactly_the_expected_members_and_no_secret(self):
        result = self.exported()
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, "\n".join(report.problems))
        self.assertEqual(report.problems, [])

        members = read_archive(result.path)
        self.assertEqual({info.name for info, _ in members}, expected_members())
        self.assertEqual(result.member_count, len(expected_members()))
        for info, data in members:
            self.assertTrue(info.isreg(), info.name)
            self.assertEqual((info.mode, info.uid, info.gid, info.uname, info.gname), (0o644, 0, 0, "", ""))
            self.assertEqual(info.mtime, int(datetime(2026, 10, 26, 10, 15, tzinfo=timezone.utc).timestamp()))
            for secret in SECRETS:
                self.assertNotIn(secret.encode(), data, f"{secret} in {info.name}")
            self.assertNotIn(DECOY.encode(), data, info.name)

        # Sorted, so two exports list the same members in the same order.
        names = [info.name for info, _ in members]
        self.assertEqual(names, sorted(names))
        # The manifest goes in as the run wrote it, byte for byte.
        archived = contents(result.path)
        self.assertEqual(archived[f"{SNAPSHOT_ID}/manifest.json"], (self.snapshot / "manifest.json").read_bytes())

    def test_the_testbed_keeps_references_usernames_and_addresses_and_counts_what_it_replaced(self):
        result = self.exported()
        text = contents(result.path)[f"{SNAPSHOT_ID}/testbed.yaml"].decode("utf-8")
        self.assertTrue(text.startswith("# Testbed exported by DiscoNet"))
        self.assertIn("comments are dropped", text)
        tree = yaml.safe_load(text)
        self.assertEqual(tree["testbed"]["credentials"]["default"],
                         {"username": "netops", "password": REDACTION_MARKER})
        self.assertEqual(tree["testbed"]["credentials"]["enable"]["password"], REDACTION_MARKER)
        self.assertEqual(tree["testbed"]["servers"]["jump"]["credentials"]["default"],
                         {"username": "jumpuser", "password": REDACTION_MARKER})
        pe1 = tree["devices"]["rbt-ald-pe1"]
        self.assertEqual(pe1["credentials"]["default"],
                         {"username": "%ENV{DISCONET_USERNAME}", "password": "%ENV{DISCONET_PASSWORD}"})
        self.assertEqual(pe1["credentials"]["enable"]["secret"], REDACTION_MARKER)
        self.assertEqual(pe1["custom"]["login_prompts"], [{"pattern": "One-time code:", "response": REDACTION_MARKER}])
        self.assertEqual(pe1["connections"]["cli"]["ip"], "192.0.2.11")
        p2 = tree["devices"]["rbt-bht-p2"]
        self.assertEqual(p2["credentials"]["default"]["password"], "%ASK{}")
        self.assertEqual(p2["custom"]["snmp_community"], REDACTION_MARKER)
        rr2 = tree["devices"]["rbt-bht-rr2"]["connections"]["cli"]
        self.assertEqual(rr2["command"], f"ssh -J jumpuser@192.0.2.50 rbt-bht-rr2 # {REDACTION_MARKER}")

        self.assertEqual(result.redacted_values, REDACTED_VALUES)
        document = json.loads(contents(result.path)[f"{SNAPSHOT_ID}/export-manifest.json"])
        self.assertEqual(document["testbed"],
                         {"file": f"{SNAPSHOT_ID}/testbed.yaml", "redacted_values": REDACTED_VALUES})

    def test_no_decoy_is_in_the_archive_and_the_unnamed_file_is_reported_as_left_out(self):
        result = self.exported()
        names = {info.name for info, _ in read_archive(result.path)}
        for decoy in ("discovered-network.html", "discovered-network.docx", "tables.xlsx", "topology.drawio",
                      "topology.svg", "topology.png", "document.json", "collect.log", "session.log",
                      "community", "sections", "disconet.db", "lifecycle.yaml", "docmeta.yaml", ".env",
                      "connect.log", "show_clock.txt"):
            self.assertFalse([name for name in names if decoy in name], decoy)
        self.assertEqual(result.left_out, ["rbt-ald-pe1/raw/show_clock.txt"])

    def test_two_exports_of_one_snapshot_at_one_time_are_the_same_bytes(self):
        first = self.exported("one.export.tar.gz")
        second = self.exported("two.export.tar.gz")
        self.assertEqual(first.path.read_bytes(), second.path.read_bytes())
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.sha256, hashlib.sha256(first.path.read_bytes()).hexdigest())
        # The gzip header carries no time and no file name.
        header = first.path.read_bytes()[:10]
        self.assertEqual(header[4:8], b"\0\0\0\0")
        self.assertFalse(header[3] & 0x08, "a file name in the gzip header")

    def test_the_export_manifest_states_the_collection(self):
        result = self.exported()
        document = json.loads(contents(result.path)[f"{SNAPSHOT_ID}/export-manifest.json"])
        self.assertEqual(document["format"], "disconet-snapshot-export")
        self.assertEqual(document["format_version"], 1)
        self.assertEqual(document["exported_at"], "2026-10-27T12:00:00Z")
        self.assertEqual(document["exported_by"], {"tool": "netstate", "version": export.__version__})
        self.assertEqual((document["snapshot_id"], document["estate"]), (SNAPSHOT_ID, "fixture"))
        self.assertEqual((document["synthetic"], document["synthetic_notice"]), (False, None))
        self.assertEqual(document["collector_version"], "0.2.0")
        self.assertEqual(document["collector_versions"], ["0.2.0"])
        self.assertIsNone(document["sources"])
        self.assertEqual(document["collection"], {"started_utc": "2026-10-26T10:15:00Z",
                                                  "finished_utc": "2026-10-26T10:21:30Z",
                                                  "finished_recorded": True})
        self.assertEqual(document["allowlist"], {"sha256": ALLOWLIST_SHA256, "recorded": "at collection"})
        self.assertEqual((document["device_count"], document["devices_connected"]), (3, 3))
        self.assertEqual(document["devices"]["rbt-bht-p2"], {"os": "junos", "platform": "MX204", "connected": True})
        self.assertEqual((document["features"], document["features_skipped"]), (["isis", "bgp"], ["ospf", "srte"]))
        self.assertTrue(document["features_recorded"])
        self.assertEqual(document["run"], {"interrupted": None, "retry_of": "", "merged_from": None,
                                           "devices_not_requested": []})
        self.assertEqual(set(document["files"]), expected_members() - {f"{SNAPSHOT_ID}/export-manifest.json"})
        version = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_version.txt"
        data = (self.snapshot / "rbt-ald-pe1" / "raw" / "show_version.txt").read_bytes()
        self.assertEqual(document["files"][version], {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})

    def test_the_default_archive_sits_beside_the_snapshot_named_after_the_estate(self):
        result = export.export_snapshot(self.snapshot, testbed=self.testbed, exported_at=EXPORTED_AT)
        self.assertEqual(result.path, self.snapshot.parent.resolve() / f"fixture-{SNAPSHOT_ID}.export.tar.gz")
        self.assertTrue(result.path.is_file())
        # No temporary file is left beside it.
        self.assertEqual(sorted(p.name for p in self.snapshot.parent.iterdir() if p.name.startswith(".")), [])
        self.assertEqual(export.default_archive_name(SNAPSHOT_ID, None), f"{SNAPSHOT_ID}.export.tar.gz")

    def test_a_run_with_no_finish_and_no_allowlist_hash_exports_with_both_said(self):
        def older(manifest):
            del manifest["finished_at"], manifest["commands_sha256"]

        self.rewrite_manifest(older)
        result = self.exported()
        document = result.export_manifest
        self.assertEqual(document["collection"]["finished_utc"], None)
        self.assertFalse(document["collection"]["finished_recorded"])
        self.assertEqual(document["allowlist"]["recorded"], "at export")
        self.assertEqual(document["allowlist"]["sha256"], ALLOWLIST_SHA256)
        self.assertEqual(document["allowlist"]["file"], str(collector.DEFAULT_COMMANDS_FILE))
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        warnings = "\n".join(report.warnings)
        self.assertIn("hashed when the snapshot was exported, not when it was collected", warnings)
        self.assertIn("finish time is not recorded", warnings)

    def test_an_interrupted_merged_retry_round_of_some_devices_exports_with_its_marks(self):
        marks = {
            "interrupted": {"reason": "interrupted (Ctrl-C or a signal)", "not_collected": ["rbt-ald-p1"]},
            "retry_of": "20261025T080000Z",
            "merged_from": [{"snapshot_id": "20261025T080000Z", "created_at": "2026-10-25T08:00:00+00:00"}],
            "devices_not_requested": ["rbt-ald-p1"],
        }
        self.rewrite_manifest(lambda manifest: manifest.update(marks))
        result = self.exported()
        self.assertEqual(result.export_manifest["run"], marks)
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        self.assertIn("interrupted", "\n".join(export.summary_lines(report)))

    def test_redaction_replaces_numbers_and_mappings_under_a_secret_and_keeps_what_holds_none(self):
        tree = {
            "devices": {"rbt-ald-p1": {
                "credentials": {"default": {"username": "netops", "password": 482193},
                                "enable": {"password": None}, "line": {"password": ""}},
                "custom": {"ssh_private_key": {"path": "/home/netops/.ssh/id_ed25519"},
                           "api_token": "%ENV{RBT_TOKEN}", "secret_answers": ["Amber-Fox-2207"]},
                "connections": {"cli": {"ip": "192.0.2.21", "note": "PIN 482193 on the label"}},
            }},
        }
        redacted, count = export.redact_testbed(tree)
        device = redacted["devices"]["rbt-ald-p1"]
        self.assertEqual(device["credentials"]["default"], {"username": "netops", "password": REDACTION_MARKER})
        self.assertIsNone(device["credentials"]["enable"]["password"])
        self.assertEqual(device["credentials"]["line"]["password"], "")
        # A mapping or a list under a secret's key keeps its shape, with every value in it replaced.
        self.assertEqual(device["custom"]["ssh_private_key"], {"path": REDACTION_MARKER})
        self.assertEqual(device["custom"]["api_token"], "%ENV{RBT_TOKEN}")
        self.assertEqual(device["custom"]["secret_answers"], [REDACTION_MARKER])
        self.assertEqual(device["connections"]["cli"],
                         {"ip": "192.0.2.21", "note": f"PIN {REDACTION_MARKER} on the label"})
        self.assertEqual(count, 4)
        # Redacting what was redacted finds nothing more.
        self.assertEqual(export.redact_testbed(redacted)[1], 0)

    def test_a_testbed_that_extends_another_is_exported_with_a_warning(self):
        self.testbed.write_text("extends: base.yaml\n" + TESTBED, encoding="utf-8")
        result = self.exported()
        self.assertIn("only this file is exported", "\n".join(result.warnings))


class ATamperedArchiveFails(ExportFixture):
    def setUp(self):
        super().setUp()
        self.good = self.exported().path
        self.bad = self.out / "altered.export.tar.gz"

    def test_a_changed_file_is_named_as_tampered(self):
        target = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_version.txt"

        def change(members, _document):
            members[target] = members[target].replace(b"7.9.2", b"7.9.9")

        rebuild(self.good, self.bad, change)
        self.assert_fails(export.verify_archive(self.bad), "tampered", target)

    def test_a_missing_file_fails(self):
        target = f"{SNAPSHOT_ID}/rbt-bht-p2/state/show_version.json"
        rebuild(self.good, self.bad, lambda members, _document: members.pop(target))
        self.assert_fails(export.verify_archive(self.bad), "missing", target)

    def test_an_extra_file_with_a_plausible_name_fails(self):
        target = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_clock.txt"
        rebuild(self.good, self.bad, lambda members, _document: members.update({target: b"12:00:00 UTC\n"}))
        self.assert_fails(export.verify_archive(self.bad), "extra", target)

    def test_a_file_dropped_from_the_archive_and_its_list_still_fails_against_manifest_json(self):
        # The archive and its file list agree with each other, and the
        # collection manifest still names the file that was taken out.
        target = f"{SNAPSHOT_ID}/rbt-ald-pe1/state/show_version.json"

        def change(members, document):
            members.pop(target)
            document["files"].pop(target)

        rebuild(self.good, self.bad, change)
        self.assert_fails(export.verify_archive(self.bad), "manifest.json names rbt-ald-pe1/state/show_version.json")

    def test_a_testbed_swapped_for_one_with_its_secrets_fails_even_with_its_hash_listed(self):
        target = f"{SNAPSHOT_ID}/testbed.yaml"

        def change(members, document):
            members[target] = TESTBED.encode("utf-8")
            listed(document, target, members[target])

        rebuild(self.good, self.bad, change)
        self.assert_fails(export.verify_archive(self.bad), f"{target} still holds")

    def test_a_file_that_is_no_gzip_tar_is_unreadable(self):
        self.bad.write_bytes(b"this is no archive\n")
        report = export.verify_archive(self.bad)
        self.assertFalse(report.ok)
        self.assertFalse(report.readable)
        self.assertIn("not a readable gzip-compressed tar", report.problems[0])
        plain = self.out / "plain.tar"
        with tarfile.open(plain, "w") as tar:
            info, data = regular(f"{SNAPSHOT_ID}/manifest.json", b"{}")
            tar.addfile(info, io.BytesIO(data))
        self.assertFalse(export.verify_archive(plain).readable)
        self.assertFalse(export.verify_archive(self.out / "absent.export.tar.gz").readable)

    def test_an_export_manifest_with_its_file_list_taken_out_fails_and_hides_no_change(self):
        # Without the list there is nothing to hold a member to: the
        # changed file must not then pass for want of a hash to differ from.
        target = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_version.txt"

        def change(members, document):
            del document["files"]
            members[target] = members[target] + b"tampered\n"

        rebuild(self.good, self.bad, change)
        report = export.verify_archive(self.bad)
        self.assert_fails(report, "the export manifest lists no files")
        self.assertFalse(report.summary["hashes_ok"])

    def test_an_archive_without_its_collection_manifest_fails_even_with_its_listing_gone(self):
        target = f"{SNAPSHOT_ID}/manifest.json"

        def change(members, document):
            members.pop(target)
            document["files"].pop(target)

        rebuild(self.good, self.bad, change)
        report = export.verify_archive(self.bad)
        self.assert_fails(report, f"the archive holds no {target}")
        # Nothing of the collection is shown from the export manifest's own say-so.
        self.assertFalse(report.summary["collection_read"])
        self.assertEqual(report.summary["device_count"], 0)
        self.assertIn("manifest.json could not be read", "\n".join(export.summary_lines(report)))

    def test_an_archive_without_its_testbed_fails_even_with_its_listing_gone(self):
        target = f"{SNAPSHOT_ID}/testbed.yaml"

        def change(members, document):
            members.pop(target)
            document["files"].pop(target)

        rebuild(self.good, self.bad, change)
        self.assert_fails(export.verify_archive(self.bad), f"the archive holds no testbed ({target})")

    def test_an_export_manifest_listing_its_own_hash_fails(self):
        target = f"{SNAPSHOT_ID}/export-manifest.json"
        rebuild(self.good, self.bad, lambda _members, document: listed(document, target, b"{}\n"))
        self.assert_fails(export.verify_archive(self.bad), f"lists {target}, which cannot carry its own hash")

    def test_an_export_manifest_of_another_format_version_fails(self):
        rebuild(self.good, self.bad, lambda _members, document: document.update(format_version=2))
        self.assert_fails(export.verify_archive(self.bad), "version 2; this verify reads")

    def test_an_export_manifest_naming_another_snapshot_or_one_that_cannot_be_a_folder_fails(self):
        for stated, words in (("20261025T080000Z", f"names snapshot 20261025T080000Z, but sits in the folder "
                                                    f"{SNAPSHOT_ID}/"),
                              ("../x", "snapshot_id '../x' cannot name a folder")):
            with self.subTest(snapshot_id=stated):
                rebuild(self.good, self.bad, lambda _members, document: document.update(snapshot_id=stated))
                self.assert_fails(export.verify_archive(self.bad), words)

    def test_a_testbed_record_naming_another_file_fails(self):
        rebuild(self.good, self.bad,
                lambda _members, document: document["testbed"].update(file=f"{SNAPSHOT_ID}/other.yaml"))
        self.assert_fails(export.verify_archive(self.bad), f"names the testbed '{SNAPSHOT_ID}/other.yaml'")

    def test_a_member_too_large_for_verify_to_read_fails(self):
        # The limit is 256 MB; a small one stands in for it rather than a large archive.
        with mock.patch.object(export, "KEEP_LIMIT", 64):
            report = export.verify_archive(self.good)
        self.assert_fails(report, f"{SNAPSHOT_ID}/manifest.json is too large for verify to read")


class TheAllowlistIsChecked(ExportFixture):
    def test_an_allowlist_other_than_the_one_collected_with_fails_and_says_which_file(self):
        result = self.exported()
        other = self.base / "other-commands.yaml"
        other.write_bytes(collector.DEFAULT_COMMANDS_FILE.read_bytes() + b"\n# one more line\n")
        report = export.verify_archive(result.path, allowlist=other)
        self.assert_fails(report, "does not match", str(other), ALLOWLIST_SHA256)
        self.assertIn("DOES NOT MATCH", "\n".join(export.summary_lines(report)))
        self.assertTrue(export.verify_archive(result.path, allowlist=collector.DEFAULT_COMMANDS_FILE).ok)

    def test_an_edited_allowlist_hash_in_the_export_manifest_fails(self):
        result = self.exported()
        bad = self.out / "allowlist.export.tar.gz"
        forged = "0" * 64
        rebuild(result.path, bad, lambda _members, document: document["allowlist"].update(sha256=forged))
        report = export.verify_archive(bad)
        self.assert_fails(report, f"manifest.json records the allowlist as sha256 {ALLOWLIST_SHA256}", forged)

    def test_an_allowlist_said_to_be_recorded_at_collection_that_was_not_fails(self):
        self.rewrite_manifest(lambda manifest: manifest.pop("commands_sha256"))
        result = self.exported()
        bad = self.out / "provenance.export.tar.gz"
        rebuild(result.path, bad, lambda _members, document: document["allowlist"].update(recorded="at collection"))
        self.assert_fails(export.verify_archive(bad), "manifest.json records no hash of it")

    def test_a_malformed_allowlist_hash_in_the_manifest_is_refused_at_export(self):
        self.rewrite_manifest(lambda manifest: manifest.update(commands_sha256="NOT-A-HASH"))
        with self.assertRaises(export.ExportRefused) as caught:
            self.exported()
        self.assertIn("commands_sha256", str(caught.exception))

    def test_a_run_held_to_a_custom_allowlist_is_exported_with_that_hash_and_verified_against_that_file(self):
        # The hash the run recorded goes into the archive as it is: not the
        # one of whatever allowlist the exporting machine has installed.
        custom = self.base / "custom-commands.yaml"
        custom.write_bytes(collector.DEFAULT_COMMANDS_FILE.read_bytes() + b"\n# trimmed for this estate\n")
        custom_sha256 = hashlib.sha256(custom.read_bytes()).hexdigest()
        self.rewrite_manifest(lambda manifest: manifest.update(commands_sha256=custom_sha256,
                                                               commands_file=str(custom)))
        result = self.exported()
        self.assertEqual(result.export_manifest["allowlist"], {"sha256": custom_sha256, "recorded": "at collection"})
        self.assertTrue(export.verify_archive(result.path, allowlist=custom).ok)
        self.assert_fails(export.verify_archive(result.path), "does not match", custom_sha256)

    def test_an_allowlist_to_compare_with_that_cannot_be_read_fails(self):
        result = self.exported()
        absent = self.base / "absent-commands.yaml"
        self.assert_fails(export.verify_archive(result.path, allowlist=absent),
                          f"could not read the allowlist {absent} to compare with")

    def test_an_allowlist_said_to_be_hashed_at_export_that_the_run_recorded_fails(self):
        result = self.exported()
        bad = self.out / "provenance.export.tar.gz"
        rebuild(result.path, bad, lambda _members, document: document["allowlist"].update(recorded="at export"))
        self.assert_fails(export.verify_archive(bad), "hashed at export, but manifest.json recorded it at collection")

    def test_an_export_manifest_with_no_usable_allowlist_hash_fails(self):
        result = self.exported()
        for record in ({"sha256": "not-a-hash", "recorded": "at collection"},
                       {"sha256": ALLOWLIST_SHA256, "recorded": "by hand"}, None):
            with self.subTest(record=record):
                bad = self.out / "no-hash.export.tar.gz"
                rebuild(result.path, bad, lambda _members, document: document.update(allowlist=record))
                self.assert_fails(export.verify_archive(bad), "records no usable allowlist hash")


class TheSignatureIsChecked(ExportFixture):
    def setUp(self):
        super().setUp()
        self.key_a = self.base / "keys" / "a.pem"
        self.key_b = self.base / "keys" / "b.pem"

    def signed(self, name: str = "signed.export.tar.gz", key: Path | None = None) -> export.ExportResult:
        return self.exported(name, sign=True, key_path=key or self.key_a)

    def test_signed_and_verified_with_the_right_key_is_ok(self):
        result = self.signed()
        self.assertTrue(result.signed)
        self.assertTrue(result.public_key_line.startswith("ed25519 "))
        self.assertIn(f"{SNAPSHOT_ID}/export-manifest.sig", contents(result.path))
        report = export.verify_archive(result.path, public_key=result.public_key_line)
        self.assertTrue(report.ok, report.problems)
        kid = signing.key_id(signing.parse_key_line(result.public_key_line))
        self.assertEqual(report.summary["signature"]["kid"], kid)
        # A file holding the line, with a note beside it, does as well.
        saved = self.base / "sender.pub"
        saved.write_text(f"# rbt-ald network team, read out by phone\n{result.public_key_line}\n", encoding="utf-8")
        self.assertTrue(export.verify_archive(result.path, public_key=str(saved)).ok)

    def test_signed_with_no_key_given_is_ok_with_a_warning_that_the_key_was_not_compared(self):
        result = self.signed()
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        kid = signing.key_id(signing.parse_key_line(result.public_key_line))
        self.assertTrue([w for w in report.warnings if "NOT compared" in w and kid in w], report.warnings)

    def test_flipped_signature_bytes_fail(self):
        result = self.signed()
        bad = self.out / "flipped.export.tar.gz"
        sig_name = f"{SNAPSHOT_ID}/export-manifest.sig"

        def change(members, _document):
            document = json.loads(members[sig_name])
            raw = bytearray(base64.b64decode(document["signature"]))
            raw[0] ^= 0x01
            document["signature"] = base64.b64encode(bytes(raw)).decode("ascii")
            members[sig_name] = json.dumps(document).encode("utf-8")

        rebuild(result.path, bad, change)
        self.assert_fails(export.verify_archive(bad), "does not verify")

    def test_signed_by_one_key_and_verified_with_another_fails(self):
        result = self.signed()
        other = signing.load_or_create(self.key_b)
        report = export.verify_archive(result.path, public_key=other.line)
        self.assert_fails(report, "not by the key given", other.kid)

    def test_an_unsigned_archive_verified_with_a_public_key_fails(self):
        result = self.exported()
        key = signing.load_or_create(self.key_a)
        self.assert_fails(export.verify_archive(result.path, public_key=key.line), "not signed")
        # Unsigned and no key asked for: ok, said to be unsigned.
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok)
        self.assertIn("not signed", "\n".join(report.warnings))

    def test_an_export_manifest_edited_after_signing_fails_even_with_its_hashes_consistent(self):
        result = self.signed()
        bad = self.out / "edited.export.tar.gz"
        rebuild(result.path, bad, lambda _members, document: document.update(exported_at="2026-10-28T09:00:00Z"))
        report = export.verify_archive(bad, public_key=result.public_key_line)
        self.assert_fails(report, "does not verify")
        self.assertFalse([p for p in report.problems if "tampered" in p or "missing" in p or "extra" in p])

    def test_the_key_is_created_0600_in_a_0700_folder_on_first_use_and_reused(self):
        first = self.exported("one.export.tar.gz", sign=True)
        path = self.home / ".config" / "disconet" / "export_ed25519.pem"
        self.assertEqual(first.key_path, path)
        self.assertTrue(first.key_created)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertTrue(path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----"))
        second = self.exported("two.export.tar.gz", sign=True)
        self.assertFalse(second.key_created)
        self.assertEqual(first.public_key_line, second.public_key_line)
        # Ed25519 is deterministic: the same snapshot signed twice is the same bytes.
        self.assertEqual(first.path.read_bytes(), second.path.read_bytes())

    def test_a_public_key_file_that_is_not_there_fails_rather_than_leaving_the_key_uncompared(self):
        result = self.signed()
        missing = self.base / "no-such-sender.pub"
        report = export.verify_archive(result.path, public_key=missing)
        self.assert_fails(report, "the --public-key given cannot be used", str(missing))
        self.assertFalse(report.summary["signature"]["compared"])
        console = io.StringIO()
        with redirect_stdout(console):
            code = cli.main(["verify", str(result.path), "--public-key", str(missing)])
        self.assertEqual(code, 1, console.getvalue())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"), "file modes and owners are POSIX's")
    def test_an_existing_key_others_can_read_or_another_user_owns_is_refused_as_ssh_refuses_one(self):
        key = signing.load_or_create(self.key_a)
        for mode in (0o644, 0o640, 0o604, 0o660):
            with self.subTest(mode=oct(mode)):
                self.key_a.chmod(mode)
                with self.assertRaises(signing.SigningError) as caught:
                    signing.load_or_create(self.key_a)
                self.assertIn(f"chmod 600 {self.key_a}", str(caught.exception))
                # And through export: refused, with nothing written.
                with self.assertRaises(export.ExportRefused):
                    self.signed("refused.export.tar.gz")
                self.assertFalse((self.out / "refused.export.tar.gz").exists())
        self.key_a.chmod(0o600)
        self.assertEqual(signing.load_or_create(self.key_a).line, key.line)
        with mock.patch.object(os, "geteuid", return_value=self.key_a.stat().st_uid + 1):
            with self.assertRaises(signing.SigningError) as caught:
                signing.load_or_create(self.key_a)
        self.assertIn("belongs to another user", str(caught.exception))
        self.assertIn(f"chmod 600 {self.key_a}", str(caught.exception))

    def test_a_key_line_whose_kid_was_edited_is_refused(self):
        line = signing.load_or_create(self.key_a).line
        alg, kid, key = line.split()
        with self.assertRaises(signing.SigningError):
            signing.parse_key_line(f"{alg} {'0' * len(kid)} {key}")

    def test_without_cryptography_signing_says_what_to_install_and_unsigned_archives_still_verify(self):
        signed = self.signed()
        unsigned = self.exported("plain.export.tar.gz")
        blocked = {name: None for name in list(sys.modules) if name.startswith("cryptography.")}
        blocked["cryptography"] = None
        with mock.patch.dict(sys.modules, blocked):
            with self.assertRaises(signing.SigningError) as caught:
                signing.load_or_create(self.key_b)
            self.assertIn("pip install cryptography", str(caught.exception))
            self.assertTrue(export.verify_archive(unsigned.path).ok)
            self.assert_fails(export.verify_archive(signed.path), "cryptography")


class NothingButTheCollectionGoesIn(ExportFixture):
    def assert_refused(self, raw_file: str, *words: str) -> None:
        """A manifest naming ``raw_file`` is refused, and nothing is written."""
        def change(manifest):
            manifest["devices"]["rbt-ald-pe1"]["commands"][0]["raw_file"] = raw_file

        self.rewrite_manifest(change)
        with self.assertRaises(export.ExportRefused) as caught:
            self.exported()
        for word in words:
            self.assertIn(word, str(caught.exception))
        self.assertEqual(list(self.out.iterdir()), [])

    def test_a_manifest_naming_a_generated_output_the_database_or_a_way_out_is_refused(self):
        outside = self.base / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        cases = (
            ("discovered-network.html", "a generated output"),
            ("rbt-ald-pe1/raw/report.docx", "a generated output"),
            ("community/index.html", "community/"),
            ("sections/01-overview.md", "a generated output"),
            ("../disconet.db", "climbs out"),
            ("rbt-ald-pe1/state/disconet.db", "the estate database"),
            ("rbt-ald-pe1/raw/../../../lifecycle.yaml", "climbs out"),
            (str(outside), "absolute"),
            (str(self.snapshot / "rbt-ald-pe1" / "raw" / "show_version.txt"), "absolute"),
            ("rbt-ald-pe1/connect.log", "a log"),
            ("rbt-ald-pe1/raw/known_hosts", "known_hosts"),
            ("rbt-ald-pe1/notes/show_version.txt", "not of the shape"),
            ("manifest.json", "not of the shape"),
        )
        for raw_file, word in cases:
            with self.subTest(raw_file=raw_file):
                self.assert_refused(raw_file, word)

    def test_a_manifest_naming_a_symlink_is_refused(self):
        link = self.snapshot / "rbt-ald-pe1" / "raw" / "linked.txt"
        link.symlink_to(self.estate / ".env")
        self.assert_refused("rbt-ald-pe1/raw/linked.txt", "symlink")
        # A folder on the way that is a link is refused as well.
        real = self.base / "elsewhere"
        shutil.copytree(self.snapshot / "rbt-bht-p2" / "raw", real)
        shutil.rmtree(self.snapshot / "rbt-bht-p2" / "raw")
        (self.snapshot / "rbt-bht-p2" / "raw").symlink_to(real)
        self.assert_refused("rbt-bht-p2/raw/show_version.txt", "passes through a symlink")

    def hand_built(self, extra: list[tuple[tarfile.TarInfo, bytes | None]], list_them: bool = True) -> Path:
        """The good archive with ``extra`` entries added, each regular one listed with its true hash."""
        good = self.exported().path
        members = contents(good)
        name = f"{SNAPSHOT_ID}/export-manifest.json"
        document = json.loads(members[name])
        if list_them:
            for info, data in extra:
                if data is not None and info.isreg():
                    listed(document, info.name, data)
        members[name] = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
        target = self.out / "hand-built.export.tar.gz"
        write_archive(target, [regular(n, d) for n, d in members.items()] + extra)
        return target

    def test_an_archive_listing_a_generated_output_or_the_database_with_its_true_hash_fails(self):
        cases = (
            (f"{SNAPSHOT_ID}/discovered-network.html", "a generated output (.html)"),
            (f"{SNAPSHOT_ID}/disconet.db", "the estate database (.db)"),
            (f"{SNAPSHOT_ID}/disconet.db-wal", "the estate database (.db-wal)"),
            (f"{SNAPSHOT_ID}/community/index.html", "a generated output (the Community report's community/ folder)"),
            (f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/report.xlsx", "a generated output (.xlsx)"),
            (f"{SNAPSHOT_ID}/collect.log", "a log"),
            (f"{SNAPSHOT_ID}/notes.txt", "not a file an export holds"),
        )
        for name, words in cases:
            with self.subTest(member=name):
                report = export.verify_archive(self.hand_built([regular(name, f"{DECOY}\n".encode())]))
                self.assert_fails(report, name, words)
                self.assertFalse([p for p in report.problems if "extra" in p], report.problems)

    def test_a_path_out_of_the_folder_a_link_a_directory_and_a_duplicate_fail(self):
        link = tarfile.TarInfo(f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/link.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../../../outside.txt"
        hard = tarfile.TarInfo(f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/hard.txt")
        hard.type = tarfile.LNKTYPE
        hard.linkname = f"{SNAPSHOT_ID}/manifest.json"
        folder = tarfile.TarInfo(f"{SNAPSHOT_ID}/rbt-ald-pe1")
        folder.type = tarfile.DIRTYPE
        version = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_version.txt"
        cases = (
            ([regular(f"{SNAPSHOT_ID}/../escape.txt", b"x\n")], "climbs out"),
            ([regular(f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/../../../escape.txt", b"x\n")], "climbs out"),
            ([regular("/tmp/escape.txt", b"x\n")], "absolute"),
            ([regular(f"{SNAPSHOT_ID}\\rbt-ald-pe1\\raw\\x.txt", b"x\n")], "backslash"),
            ([regular("20991231T000000Z/rbt-ald-pe1/raw/show_version.txt", b"x\n")], "outside the archive's folder"),
            ([(link, None)], "a symlink"),
            ([(hard, None)], "a hard link"),
            ([(folder, None)], "a directory"),
            ([regular(version, (self.snapshot / "rbt-ald-pe1" / "raw" / "show_version.txt").read_bytes())],
             "appears 2 times"),
        )
        for extra, words in cases:
            with self.subTest(words=words):
                self.assert_fails(export.verify_archive(self.hand_built(extra, list_them=False)), words)


class TheSummaryIsRederived(ExportFixture):
    def test_a_summary_that_says_a_demo_is_not_one_fails(self):
        notice = "Demo network (mock-up). Riverbend Telecom is an invented operator."
        self.rewrite_manifest(lambda manifest: manifest.update(synthetic=True, synthetic_notice=notice))
        result = self.exported()
        bad = self.out / "forged.export.tar.gz"
        rebuild(result.path, bad, lambda _members, document: document.update(synthetic=False, synthetic_notice=None))
        self.assert_fails(export.verify_archive(bad), "synthetic", "synthetic_notice")

    def test_a_device_whose_os_was_changed_in_the_summary_fails(self):
        result = self.exported()
        bad = self.out / "forged.export.tar.gz"
        rebuild(result.path, bad, lambda _members, document: document["devices"]["rbt-bht-p2"].update(os="iosxr"))
        self.assert_fails(export.verify_archive(bad), "rbt-bht-p2's os is 'iosxr'", "'junos'")

    def test_counts_features_times_and_run_marks_are_each_rederived(self):
        result = self.exported()
        changes = {
            "device_count": 4,
            "devices_connected": 2,
            "features": ["isis", "bgp", "srte"],
            "collection": {"started_utc": "2026-10-26T10:15:00Z", "finished_utc": None, "finished_recorded": False},
            "run": {"interrupted": None, "retry_of": "", "merged_from": None, "devices_not_requested": ["rbt-ald-p1"]},
            "collector_version": "9.9.9",
            "collector_versions": ["9.9.9"],
            "sources": [],
            "features_recorded": False,
            "estate": "another",
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                bad = self.out / f"forged-{key}.export.tar.gz"
                rebuild(result.path, bad, lambda _members, document: document.update({key: value}))
                self.assert_fails(export.verify_archive(bad), f"export-manifest.json says {key}")

    def test_a_demo_snapshot_is_marked_in_the_export_manifest_and_the_summary(self):
        notice = "Demo network (mock-up). Riverbend Telecom is an invented operator."
        self.rewrite_manifest(lambda manifest: manifest.update(synthetic=True, synthetic_notice=notice))
        result = self.exported()
        self.assertTrue(result.synthetic)
        self.assertEqual(result.synthetic_notice, notice)
        stated = result.export_manifest
        self.assertEqual((stated["synthetic"], stated["synthetic_notice"]), (True, notice))
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        lines = export.summary_lines(report)
        self.assertIn(f"DEMO:       {notice}", lines)
        self.assertTrue([w for w in report.warnings if notice in w])

    def test_a_run_from_before_feature_selection_is_said_to_have_read_everything_not_nothing(self):
        def older(manifest):
            del manifest["features"], manifest["features_skipped"]

        self.rewrite_manifest(older)
        result = self.exported()
        document = result.export_manifest
        self.assertEqual((document["features"], document["features_recorded"], document["features_skipped"]),
                         (None, False, []))
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        lines = "\n".join(export.summary_lines(report))
        self.assertIn("Features:   not recorded (collected before feature selection, which read everything)", lines)
        self.assertNotIn("collected: none", lines)
        bad = self.out / "forged-features.export.tar.gz"
        rebuild(result.path, bad, lambda _members, document: document.update(features=[], features_recorded=True))
        self.assert_fails(export.verify_archive(bad), "export-manifest.json says features is []")


OLDER_RUN = "20261025T080000Z"
NEWER_RUN = "20261026T100500Z"
OTHER_ALLOWLIST_SHA256 = hashlib.sha256(b"an allowlist other than netstate's\n").hexdigest()


class AMergeIsDescribedByItsRuns(ExportFixture):
    """A snapshot `disconet merge` (or `retry`) wrote, by the merge contract: each run's version, finish and hash."""

    def merged(self, older: dict, newer: dict) -> None:
        """Make the fixture's manifest a merge of two runs, as merge.py writes one from dict(newest.manifest)."""
        sources = [
            {"snapshot_id": OLDER_RUN, "created_at": "2026-10-25T08:00:00+00:00", "utc_offset_minutes": 0,
             "root": str(self.base / "snapshots" / OLDER_RUN), "devices_taken": ["rbt-ald-pe1", "rbt-bht-p2"],
             **older},
            {"snapshot_id": NEWER_RUN, "created_at": "2026-10-26T10:05:00+00:00", "utc_offset_minutes": 0,
             "root": str(self.base / "snapshots" / NEWER_RUN), "devices_taken": ["rbt-bht-rr2"], **newer},
        ]
        finishes = [source.get("finished_at") for source in sources]
        hashes = {source.get("commands_sha256") for source in sources}

        def change(manifest):
            manifest.pop("netstate_version")
            manifest.update(
                disconet_version="1.4.0", created_at="2026-10-26T10:05:00+00:00",
                collected_from="2026-10-25T08:00:00+00:00", collected_to="2026-10-26T10:05:00+00:00",
                merged_from=sources,
                finished_at=max(finishes) if all(finishes) else None,
                commands_sha256=next(iter(hashes)) if len(hashes) == 1 and None not in hashes else None,
            )

        self.rewrite_manifest(change)

    def test_runs_that_agree_give_one_version_the_whole_window_and_one_hash(self):
        self.merged({"collector_versions": ["0.2.0"], "finished_at": "2026-10-25T08:09:00+00:00",
                     "commands_sha256": ALLOWLIST_SHA256},
                    {"collector_versions": ["0.2.0"], "finished_at": "2026-10-26T10:07:30.5+00:00",
                     "commands_sha256": ALLOWLIST_SHA256})
        result = self.exported()
        document = result.export_manifest
        self.assertEqual((document["collector_version"], document["collector_versions"]), ("0.2.0", ["0.2.0"]))
        self.assertEqual(document["collection"], {"started_utc": "2026-10-25T08:00:00Z",
                                                  "finished_utc": "2026-10-26T10:07:30Z", "finished_recorded": True})
        self.assertEqual(document["sources"], [
            {"snapshot_id": OLDER_RUN, "started_utc": "2026-10-25T08:00:00Z", "finished_utc": "2026-10-25T08:09:00Z",
             "collector_versions": ["0.2.0"], "commands_sha256": ALLOWLIST_SHA256},
            {"snapshot_id": NEWER_RUN, "started_utc": "2026-10-26T10:05:00Z", "finished_utc": "2026-10-26T10:07:30Z",
             "collector_versions": ["0.2.0"], "commands_sha256": ALLOWLIST_SHA256},
        ])
        self.assertEqual(document["allowlist"], {"sha256": ALLOWLIST_SHA256, "recorded": "at collection"})
        # Every member carries the time the collection began: the older run's.
        start = int(datetime(2026, 10, 25, 8, 0, tzinfo=timezone.utc).timestamp())
        self.assertEqual({info.mtime for info, _ in read_archive(result.path)}, {start})
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        lines = export.summary_lines(report)
        self.assertIn("Collected:  by netstate 0.2.0, 2026-10-25T08:00:00Z to 2026-10-26T10:07:30Z (UTC)", lines)
        self.assertIn("Merged:     2 run(s)", lines)
        self.assertTrue([line for line in lines if line.startswith(f"  {OLDER_RUN}  2026-10-25T08:00:00Z to "
                                                                     f"2026-10-25T08:09:00Z, by netstate 0.2.0")])

    def test_runs_that_differ_are_recorded_one_by_one_and_verify_names_the_one_that_does_not_match(self):
        self.merged({"collector_versions": ["0.2.0"], "finished_at": "2026-10-25T08:09:00+00:00",
                     "commands_sha256": OTHER_ALLOWLIST_SHA256},
                    {"collector_versions": ["0.3.0"], "finished_at": "2026-10-26T10:07:30+00:00",
                     "commands_sha256": ALLOWLIST_SHA256})
        result = self.exported()
        document = result.export_manifest
        self.assertEqual((document["collector_version"], document["collector_versions"]), (None, ["0.2.0", "0.3.0"]))
        self.assertEqual(document["allowlist"], {
            "sha256": None, "recorded": "per source",
            "per_source": {OLDER_RUN: OTHER_ALLOWLIST_SHA256, NEWER_RUN: ALLOWLIST_SHA256},
        })
        self.assertTrue([w for w in result.warnings if "2 different allowlists" in w], result.warnings)
        report = export.verify_archive(result.path)
        self.assert_fails(report, f"merged run {OLDER_RUN} was held to the allowlist with sha256 "
                                  f"'{OTHER_ALLOWLIST_SHA256}'")
        self.assertFalse([p for p in report.problems if NEWER_RUN in p], report.problems)
        lines = export.summary_lines(report)
        self.assertTrue([line for line in lines if line.startswith("Allowlist:  recorded per merged run, 2 of 2 "
                                                                     "with a hash; NOT all of them match")], lines)
        self.assertTrue([line for line in lines if line.startswith("Collected:  by netstate 0.2.0 and 0.3.0, ")])
        other = self.base / "other-commands.yaml"
        other.write_bytes(b"an allowlist other than netstate's\n")
        report = export.verify_archive(result.path, allowlist=other)
        self.assert_fails(report, f"merged run {NEWER_RUN} was held to the allowlist")
        self.assertFalse([p for p in report.problems if OLDER_RUN in p], report.problems)
        absent = self.base / "absent-commands.yaml"
        self.assert_fails(export.verify_archive(result.path, allowlist=absent),
                          f"could not read the allowlist {absent} to compare with")

    def test_a_run_that_recorded_no_hash_or_finish_is_warned_about_by_name(self):
        self.merged({}, {"collector_versions": ["0.2.0"], "finished_at": "2026-10-26T10:07:30+00:00",
                         "commands_sha256": ALLOWLIST_SHA256})
        result = self.exported()
        document = result.export_manifest
        self.assertEqual(document["allowlist"]["per_source"], {OLDER_RUN: None, NEWER_RUN: ALLOWLIST_SHA256})
        self.assertEqual((document["collector_version"], document["collector_versions"]), (None, ["0.2.0"]))
        self.assertIsNone(document["collection"]["finished_utc"])
        self.assertTrue([w for w in result.warnings if f"merged run {OLDER_RUN} recorded no hash" in w])
        self.assertTrue([w for w in result.warnings if w.startswith("the merge records no finish time")],
                        result.warnings)
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        self.assertTrue([w for w in report.warnings if f"merged run {OLDER_RUN} recorded no hash" in w])
        self.assertTrue([w for w in report.warnings if "merge's finish time is not recorded" in w])
        lines = export.summary_lines(report)
        self.assertTrue([line for line in lines if line.startswith("Allowlist:  recorded per merged run, 1 of 2 "
                                                                     "with a hash; all of them match")], lines)
        self.assertTrue([line for line in lines
                         if line.startswith("Collected:  by netstate 0.2.0 and runs that recorded none, ")])
        self.assertTrue([line for line in lines if line.startswith(f"  {OLDER_RUN}  ")
                         and "finish not recorded, by netstate ?, allowlist hash not recorded" in line], lines)

    def test_a_run_that_is_itself_a_merge_brings_every_version_it_was_made_of(self):
        # Read as merge.py writes the list: distinct texts, sorted, nothing else.
        self.merged({"collector_versions": ["0.2.0", "0.1.9", "", 7, "0.2.0"],
                     "finished_at": "2026-10-25T08:09:00+00:00", "commands_sha256": ALLOWLIST_SHA256},
                    {"collector_versions": ["0.2.0"], "finished_at": "2026-10-26T10:07:30+00:00",
                     "commands_sha256": ALLOWLIST_SHA256})
        document = self.exported().export_manifest
        self.assertEqual((document["collector_version"], document["collector_versions"]), (None, ["0.1.9", "0.2.0"]))
        self.assertEqual(document["allowlist"], {"sha256": ALLOWLIST_SHA256, "recorded": "at collection"})

    def test_a_merge_never_names_the_merging_disconet_as_its_collector(self):
        self.merged({}, {})
        result = self.exported()
        self.assertEqual((result.export_manifest["collector_version"], result.export_manifest["collector_versions"]),
                         (None, []))
        # No run recorded a hash: hashed at export, as for an older single run.
        self.assertEqual(result.export_manifest["allowlist"]["recorded"], "at export")
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        self.assertTrue([line for line in export.summary_lines(report)
                         if line.startswith("Collected:  by netstate ? (no merged run recorded its version), ")])

    def test_a_run_collected_before_the_netstate_rename_names_the_disconet_that_collected_it(self):
        for key in ("disconet_version", "version"):
            with self.subTest(key=key):
                def older(manifest):
                    manifest.pop("netstate_version", None)
                    manifest.pop("disconet_version", None)
                    manifest[key] = "1.1.0"

                self.rewrite_manifest(older)
                result = self.exported(f"{key}.export.tar.gz")
                self.assertEqual((result.export_manifest["collector_version"],
                                  result.export_manifest["collector_versions"]), ("1.1.0", ["1.1.0"]))
                report = export.verify_archive(result.path)
                self.assertTrue(report.ok, report.problems)
                self.assertTrue([line for line in export.summary_lines(report)
                                 if line.startswith("Collected:  by netstate 1.1.0, ")])

    def test_what_the_export_manifest_says_of_the_runs_is_rederived_from_manifest_json(self):
        self.merged({"collector_versions": ["0.2.0"], "commands_sha256": OTHER_ALLOWLIST_SHA256},
                    {"collector_versions": ["0.3.0"], "commands_sha256": ALLOWLIST_SHA256})
        result = self.exported()
        cases = (
            (lambda document: document.update(collector_version="0.3.0"), "says collector_version is '0.3.0'"),
            (lambda document: document.update(collector_versions=["0.3.0"]), "says collector_versions is"),
            (lambda document: document["sources"][0].update(commands_sha256=ALLOWLIST_SHA256), "says sources is"),
            (lambda document: document["allowlist"]["per_source"].update({OLDER_RUN: ALLOWLIST_SHA256}),
             "are not the ones manifest.json's merged_from records"),
            (lambda document: document.update(allowlist={"sha256": ALLOWLIST_SHA256, "recorded": "at collection"}),
             "manifest.json records the allowlist per merged run, but the export manifest says one hash"),
        )
        for forge, words in cases:
            with self.subTest(words=words):
                bad = self.out / "forged-merge.export.tar.gz"
                rebuild(result.path, bad, lambda _members, document: forge(document))
                self.assert_fails(export.verify_archive(bad), words)

    def test_a_single_run_said_to_be_recorded_per_merged_run_fails(self):
        result = self.exported()
        bad = self.out / "forged-per-source.export.tar.gz"
        rebuild(result.path, bad, lambda _members, document: document.update(allowlist={
            "sha256": None, "recorded": "per source", "per_source": {SNAPSHOT_ID: ALLOWLIST_SHA256}}))
        self.assert_fails(export.verify_archive(bad), "recorded per merged run, but manifest.json records one hash")

    def test_a_merged_runs_hash_that_is_no_sha256_is_refused_at_export(self):
        self.merged({"commands_sha256": "NOT-A-HASH"}, {"commands_sha256": ALLOWLIST_SHA256})
        with self.assertRaises(export.ExportRefused) as caught:
            self.exported()
        self.assertIn(f"merged run {OLDER_RUN}'s commands_sha256", str(caught.exception))


class VerifyNeverRaises(ExportFixture):
    """The archive is someone else's: whatever it holds is reported, never a traceback."""

    def run_verify(self, archive: Path) -> tuple[int, str]:
        console = io.StringIO()
        with redirect_stdout(console):
            code = cli.main(["verify", str(archive)])
        return code, console.getvalue()

    def test_a_manifest_whose_fields_are_of_the_wrong_type_exports_and_verifies_with_its_summary(self):
        odd = {"merged_from": 3, "interrupted": "yes", "features": "isis", "features_skipped": {"isis": 1},
               "devices_not_requested": 5, "retry_of": ["x"], "finished_at": 12, "synthetic_notice": ["x"],
               "collected_from": False, "netstate_version": 2}

        def change(manifest):
            manifest.update(odd)
            manifest["devices"]["rbt-ald-p1"] = 3

        self.rewrite_manifest(change)
        result = self.exported()
        document = result.export_manifest
        self.assertEqual(document["run"]["merged_from"], [])
        self.assertEqual((document["sources"], document["collector_versions"]), ([], []))
        self.assertIsNone(document["run"]["interrupted"])
        self.assertEqual(document["devices"]["rbt-ald-p1"], {"os": None, "platform": None, "connected": False})
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        self.assertIn("Result:     OK", export.summary_lines(report))
        code, said = self.run_verify(result.path)
        self.assertEqual(code, 0, said)

    def test_an_archive_with_no_manifest_json_and_an_export_manifest_of_the_wrong_types_fails_cleanly(self):
        good = self.exported().path
        bad = self.out / "odd.export.tar.gz"
        target = f"{SNAPSHOT_ID}/manifest.json"

        def change(members, document):
            members.pop(target)
            document["files"].pop(target)
            document.update(devices=["rbt-ald-pe1"], collection="today", run=3, sources="x", features=5,
                            synthetic=True, exported_by="me", allowlist=[], testbed=4)

        rebuild(good, bad, change)
        report = export.verify_archive(bad)
        self.assert_fails(report, f"the archive holds no {target}")
        lines = export.summary_lines(report)
        self.assertIn("Result:     FAILED", lines[-len(report.problems) - 1])
        self.assertFalse([line for line in lines if line.startswith("Summary:    cannot be shown")], lines)
        code, said = self.run_verify(bad)
        self.assertEqual(code, 1, said)

    def test_an_error_nobody_foresaw_is_a_problem_of_the_report_not_a_traceback(self):
        archive = self.exported().path
        with mock.patch.object(export, "_testbed_check", side_effect=ValueError("unforeseen")):
            report = export.verify_archive(archive)
        self.assertFalse(report.ok)
        self.assertIn("the archive could not be checked: ValueError", report.problems)
        self.assertIn("Result:     FAILED (1 problem(s))", export.summary_lines(report))

    def test_summary_lines_of_a_report_filled_in_by_hand_still_gives_the_result(self):
        odd = {"devices": ["a"], "collection": "x", "run": 4, "allowlist": [], "signature": 1,
               "sources": [3, None], "features": 5, "exported_by": "me"}
        lines = export.summary_lines(export.VerifyReport(path=Path("x"), problems=["p"], summary=odd))
        self.assertEqual(lines[-2:], ["Result:     FAILED (1 problem(s))", "  - p"])
        self.assertFalse([line for line in lines if line.startswith("Summary:    cannot be shown")], lines)
        # A value no line expects is caught, and the result still given.
        broken = export.VerifyReport(path=Path("x"), ok=True, summary={"archive": {"bytes": "many"}})
        self.assertEqual(export.summary_lines(broken),
                         ["Archive:    x", "Summary:    cannot be shown (ValueError)", "Result:     OK"])


class ExportRefusesWhatItCannotStand(ExportFixture):
    def test_a_pruned_run_is_refused_with_the_pruned_message(self):
        for device in RAW:
            for folder in ("raw", "state"):
                shutil.rmtree(self.snapshot / device / folder, ignore_errors=True)
        self.assertTrue(store.files_pruned(self.snapshot))
        with self.assertRaises(export.ExportRefused) as caught:
            self.exported()
        self.assertIn("pruned into the estate database", str(caught.exception))
        self.assertIn("needs them on disk", str(caught.exception))
        self.assertEqual(list(self.out.iterdir()), [])

    def test_a_missing_file_is_refused_and_named(self):
        (self.snapshot / "rbt-bht-p2" / "raw" / "show_configuration.txt").unlink()
        with self.assertRaises(export.ExportRefused) as caught:
            self.exported()
        self.assertIn("rbt-bht-p2/raw/show_configuration.txt", str(caught.exception))
        self.assertNotIn("pruned", str(caught.exception))

    def test_no_testbed_is_refused_with_the_advice_to_pass_one(self):
        self.testbed.unlink()
        with self.assertRaises(export.ExportRefused) as caught:
            export.export_snapshot(self.snapshot, output=self.out / "x.export.tar.gz")
        self.assertIn("--testbed", str(caught.exception))
        with self.assertRaises(export.ExportRefused):
            export.export_snapshot(self.snapshot, testbed=self.base / "absent.yaml",
                                   output=self.out / "x.export.tar.gz")
        self.assertEqual(list(self.out.iterdir()), [])

    def test_the_testbed_the_manifest_names_is_used_when_none_is_given(self):
        result = export.export_snapshot(self.snapshot, output=self.out / "x.export.tar.gz", exported_at=EXPORTED_AT)
        self.assertEqual(result.testbed_source, self.testbed)
        self.assertEqual(result.redacted_values, REDACTED_VALUES)

    def test_an_archive_inside_the_snapshot_is_refused_before_a_key_is_made(self):
        key = self.base / "keys" / "never.pem"
        with self.assertRaises(export.ExportRefused):
            export.export_snapshot(self.snapshot, testbed=self.testbed, output=self.snapshot / "x.export.tar.gz",
                                   sign=True, key_path=key)
        self.assertFalse(key.exists())
        self.assertFalse((self.snapshot / "x.export.tar.gz").exists())

    def test_a_manifest_with_no_created_at_or_a_snapshot_id_that_cannot_name_a_folder_is_refused(self):
        path = self.snapshot / "manifest.json"
        as_written = path.read_bytes()
        for change, words in ((lambda manifest: manifest.pop("created_at"), "records no readable created_at"),
                              (lambda manifest: manifest.update(created_at="yesterday"), "no readable created_at"),
                              (lambda manifest: manifest.update(snapshot_id="../x"), "'../x' cannot name a folder")):
            with self.subTest(words=words):
                self.rewrite_manifest(change)
                with self.assertRaises(export.ExportRefused) as caught:
                    self.exported()
                self.assertIn(words, str(caught.exception))
                self.assertEqual(list(self.out.iterdir()), [])
                path.write_bytes(as_written)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX's")
    def test_a_named_file_that_is_a_named_pipe_is_refused_without_being_opened(self):
        named = self.snapshot / "rbt-bht-p2" / "raw" / "show_configuration.txt"
        named.unlink()
        os.mkfifo(named)
        with self.assertRaises(export.ExportRefused) as caught:
            self.exported()
        # Refused by the check of what the manifest names, before any file is opened.
        self.assertIn(f"{SNAPSHOT_ID} cannot be exported as it stands", str(caught.exception))
        self.assertIn("'rbt-bht-p2/raw/show_configuration.txt' (named for rbt-bht-p2's 'show configuration') "
                      "is not a regular file", str(caught.exception))
        self.assertEqual(list(self.out.iterdir()), [])

    def test_a_file_removed_swapped_or_changed_after_it_was_hashed_is_refused_and_nothing_is_written(self):
        # Between _file_member hashing a file and _write_archive packing it,
        # the file goes, becomes a link, or keeps its size and changes.
        victim = self.snapshot / "rbt-bht-p2" / "state" / "show_version.json"
        as_written = victim.read_bytes()
        original = export._write_archive

        def removed() -> None:
            victim.unlink()

        def swapped() -> None:
            victim.unlink()
            victim.symlink_to(self.snapshot / "manifest.json")

        def rewritten() -> None:
            victim.write_bytes(bytes(reversed(as_written)))

        def piped() -> None:
            # Opening a named pipe to read waits for a writer: the export
            # must refuse it, not hang on it.
            victim.unlink()
            os.mkfifo(victim)

        for change in (removed, swapped, rewritten) + ((piped,) if hasattr(os, "mkfifo") else ()):
            with self.subTest(change=change.__name__):
                def interfere(output, members, mtime):
                    change()
                    return original(output, members, mtime)

                with mock.patch.object(export, "_write_archive", interfere):
                    with self.assertRaises(export.ExportRefused) as caught:
                        self.exported()
                self.assertIn("rbt-bht-p2/state/show_version.json changed while it was being exported",
                              str(caught.exception))
                self.assertEqual(list(self.out.iterdir()), [])
                victim.unlink(missing_ok=True)
                victim.write_bytes(as_written)

    def test_an_output_ending_in_a_separator_is_a_directory_and_one_not_there_is_refused(self):
        made = self.base / "exports"
        made.mkdir()
        for given in (f"{made}{os.sep}", str(made)):
            with self.subTest(output=given):
                result = export.export_snapshot(self.snapshot, testbed=self.testbed, output=given,
                                                exported_at=EXPORTED_AT)
                self.assertEqual(result.path, made / f"fixture-{SNAPSHOT_ID}.export.tar.gz")
                self.assertTrue(result.path.is_file())
        absent = self.base / "not-yet"
        with self.assertRaises(export.ExportRefused) as caught:
            export.export_snapshot(self.snapshot, testbed=self.testbed, output=f"{absent}/", exported_at=EXPORTED_AT)
        self.assertIn("names a directory, and there is none there", str(caught.exception))
        self.assertFalse(absent.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX's")
    def test_an_output_that_is_neither_a_file_nor_a_directory_is_refused_and_left_in_place(self):
        pipe = self.out / "pipe.export.tar.gz"
        os.mkfifo(pipe)
        with self.assertRaises(export.ExportRefused) as caught:
            export.export_snapshot(self.snapshot, testbed=self.testbed, output=pipe, exported_at=EXPORTED_AT)
        self.assertIn("is not a regular file", str(caught.exception))
        self.assertTrue(stat.S_ISFIFO(pipe.lstat().st_mode))

    def test_a_testbed_naming_none_of_the_runs_devices_is_exported_with_a_warning(self):
        other = self.base / "other-network.yaml"
        other.write_text(
            "testbed:\n  name: elsewhere\ndevices:\n  rbt-glm-ce1:\n    os: iosxe\n"
            "    connections:\n      cli:\n        protocol: ssh\n        ip: 198.51.100.40\n",
            encoding="utf-8",
        )
        result = self.exported(testbed=other)
        self.assertTrue([w for w in result.warnings if "names none of this run's 3 device(s)" in w
                         and "another network" in w], result.warnings)
        self.assertFalse([w for w in self.exported("own.export.tar.gz").warnings if "another network" in w])
        # A device renamed from the placeholder the testbed calls it by is matched by that name.
        self.rewrite_manifest(lambda manifest: manifest["devices"]["rbt-ald-pe1"].update(testbed_name="rbt-glm-ce1"))
        self.assertFalse([w for w in self.exported("renamed.export.tar.gz", testbed=other).warnings
                          if "another network" in w])


class TheCommandLine(ExportFixture):
    def run_cli(self, *argv: str) -> tuple[int, str]:
        console = io.StringIO()
        with redirect_stdout(console):
            code = cli.main(list(argv))
        return code, console.getvalue()

    def test_export_then_verify_exit_0_and_a_tampered_archive_exits_1(self):
        archive = self.out / "cli.export.tar.gz"
        code, said = self.run_cli("export", "--snapshot", str(self.snapshot), "--testbed", str(self.testbed),
                                  "--output", str(archive))
        self.assertEqual(code, 0, said)
        for words in (str(archive), "SHA-256:", f"{REDACTED_VALUES} credential value(s) replaced",
                      "rbt-ald-pe1/raw/show_clock.txt", "age -r", "docs/RUN-GUIDE.md"):
            self.assertIn(words, said)
        self.assertNotIn("Public key", said)
        code, said = self.run_cli("verify", str(archive))
        self.assertEqual(code, 0, said)
        self.assertIn("Result:     OK", said)

        bad = self.out / "bad.export.tar.gz"
        target = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_version.txt"
        rebuild(archive, bad, lambda members, _document: members.update({target: b"changed\n"}))
        code, said = self.run_cli("verify", str(bad))
        self.assertEqual(code, 1, said)
        self.assertIn("FAILED", said)
        self.assertIn(target, said)

    def test_verify_exits_2_for_a_missing_file_or_one_that_is_not_a_gzip_tar(self):
        code, said = self.run_cli("verify", str(self.out / "absent.export.tar.gz"))
        self.assertEqual(code, 2, said)
        junk = self.out / "junk.export.tar.gz"
        junk.write_bytes(b"\x1f\x8b not really gzip")
        code, said = self.run_cli("verify", str(junk))
        self.assertEqual(code, 2, said)

    def test_export_exits_2_when_refused_and_writes_nothing(self):
        self.testbed.unlink()
        code, said = self.run_cli("export", "--snapshot", str(self.snapshot),
                                  "--output", str(self.out / "x.export.tar.gz"))
        self.assertEqual(code, 2, said)
        self.assertIn("Export refused", said)
        self.assertEqual(list(self.out.iterdir()), [])


    def test_key_implies_sign(self):
        archive = self.out / "keyed.export.tar.gz"
        key = self.base / "chosen.pem"
        code, said = self.run_cli("export", "--snapshot", str(self.snapshot), "--testbed", str(self.testbed),
                                  "--output", str(archive), "--key", str(key))
        self.assertEqual(code, 0, said)
        self.assertTrue(key.is_file())
        self.assertIn(f"{SNAPSHOT_ID}/export-manifest.sig", contents(archive))

    def test_verify_needs_no_estate_even_when_one_is_named_that_does_not_exist(self):
        archive = self.exported().path
        with mock.patch.dict(os.environ, {"DISCONET_ESTATE": "no-such-estate"}):
            code, said = self.run_cli("verify", str(archive))
        self.assertEqual(code, 0, said)

    def test_verify_runs_in_a_python_without_pyats(self):
        archive = self.exported().path
        script = (
            "import sys\n"
            "for name in ('pyats', 'genie', 'unicon'):\n"
            "    sys.modules[name] = None\n"
            "from netstate import cli\n"
            "sys.exit(cli.main(['verify', sys.argv[1]]))\n"
        )
        ran = subprocess.run([sys.executable, "-c", script, str(archive)], capture_output=True, text=True,
                             timeout=300, cwd=REPO, env={**os.environ, "DISCONET_ESTATE": ""})
        self.assertEqual(ran.returncode, 0, ran.stdout[-2000:] + ran.stderr[-2000:])
        self.assertIn("Result:     OK", ran.stdout)


if __name__ == "__main__":
    unittest.main()
