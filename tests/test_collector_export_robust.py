"""WS3: `verify` against archives no export writes, malformed, inconsistent or holding more than they list.

The archive is a prospect's file, and verify is the owner's one check of
it, so whatever it is handed must end in one of two ways: a FAILED report
whose problem names what is wrong, or OK where what the archive holds, once
unpacked, is exactly what was verified. Never a traceback, and never an
archive that a tar or a JSON reader other than verify's sees differently.

Each case starts from a real export of test_collector_export's fixture
estate (three demo devices at documentation addresses) and is rebuilt by
hand with tarfile and gzip: a name held twice; names with `./`, a trailing
slash, a NUL or an escape in them, or long ones in GNU or pax form; pax
headers that rename or resize a member; FIFOs, devices and sparse members;
bytes after the tar's end blocks, after the gzip stream, or in a second
gzip member; JSON with a key held twice or a key export never writes;
sizes and hashes of the wrong type; a file of the collection's shape that
manifest.json does not name, or a top file the export manifest does not
list; a signature file with more in it than export writes; an empty or
malformed --public-key. And what verify prints, which is made of the
archive's names and values, holds no character a terminal obeys.
"""

from __future__ import annotations

import copy
import gzip
import io
from contextlib import redirect_stdout
import json
import tarfile
import unicodedata
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock


from netstate import cli
from tests.test_collector_export import SNAPSHOT_ID, ExportFixture, contents, listed, regular
from netstate import export, signing

MANIFEST = f"{SNAPSHOT_ID}/manifest.json"
DOCUMENT = f"{SNAPSHOT_ID}/export-manifest.json"
SIGNATURE = f"{SNAPSHOT_ID}/export-manifest.sig"
VERSION = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_version.txt"
# A tar member the fixture never wrote, of a shape a collection writes.
CLOCK = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_clock.txt"

Entry = tuple[tarfile.TarInfo, "bytes | None"]


def tar_bytes(entries: list[Entry], form: int = tarfile.PAX_FORMAT) -> bytes:
    """The entries as one uncompressed tar, in order; a file's size is its bytes' unless a pax header sets it."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=form) as tar:
        for info, data in entries:
            info = copy.copy(info)
            if data is None:
                tar.addfile(info)
                continue
            if "size" not in info.pax_headers:
                info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def entry(name: str, kind: bytes, **attributes: Any) -> Entry:
    info = tarfile.TarInfo(name)
    info.type = kind
    for key, value in attributes.items():
        setattr(info, key, value)
    return info, None


def with_pax(name: str, data: bytes, **headers: str) -> Entry:
    info, data = regular(name, data)
    info.pax_headers = dict(headers)
    return info, data


def listing(*extra: Entry) -> Callable[[dict[str, bytes], dict], None]:
    """A change that lists each of ``extra`` in the export manifest with its true hash."""
    def change(_members: dict[str, bytes], document: dict) -> None:
        for info, data in extra:
            listed(document, info.name, data)
    return change


def data_of(entries: list[Entry], name: str) -> bytes:
    return next(data for info, data in entries if info.name == name)


def json_bytes(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")


def with_key_twice(data: bytes, key: str, first: Any) -> bytes:
    """A JSON object's bytes with ``key`` written once more, as its first key, holding ``first``."""
    return data.replace(b"{", b"{" + json.dumps(key).encode() + b": " + json.dumps(first).encode() + b",", 1)


def no_terminal_control(text: str) -> bool:
    return not any(unicodedata.category(character) in ("Cc", "Cf") for character in text.replace("\n", ""))


class HandBuiltArchives(ExportFixture):
    """The fixture exported once, signed, and every case rebuilt from its members."""

    def setUp(self):
        super().setUp()
        result = self.exported(sign=True, key_path=self.base / "keys" / "sender.pem")
        self.good = result.path
        self.key_line = result.public_key_line
        self.key = signing.load_or_create(self.base / "keys" / "sender.pem")
        self.members = contents(self.good)
        self.count = 0

    def entries(self, change: Callable[[dict[str, bytes], dict], None] | None = None, extra: list[Entry] = (),
                signed: bool = False, raw_document: bytes | None = None) -> list[Entry]:
        """The good archive's members with ``change`` applied, ``extra`` after them, re-signed or unsigned.

        The export manifest is written back from the dict ``change`` was
        given (or is ``raw_document``); the signature is dropped unless
        ``signed``, when it is made again over the new export manifest, so
        that a case tests the check it is about and not the signature.
        """
        members = dict(self.members)
        document = json.loads(members[DOCUMENT])
        members.pop(SIGNATURE)
        if change is not None:
            change(members, document)
        members[DOCUMENT] = raw_document if raw_document is not None else json_bytes(document)
        if signed:
            members[SIGNATURE] = signing.signature_document(self.key, members[DOCUMENT])
        return [regular(name, data) for name, data in members.items()] + list(extra)

    def archive(self, entries: list[Entry] | None = None, form: int = tarfile.PAX_FORMAT,
                tar: bytes | None = None, after: bytes = b"") -> Path:
        """``entries`` (or ``tar``, already a tar) gzip-compressed, with ``after`` appended to the gzip stream."""
        self.count += 1
        path = self.out / f"case-{self.count}.export.tar.gz"
        path.write_bytes(gzip.compress(tar if tar is not None else tar_bytes(entries, form), mtime=0) + after)
        return path

    def run_cli(self, *argv: str) -> tuple[int, str]:
        console = io.StringIO()
        with redirect_stdout(console):
            code = cli.main(list(argv))
        return code, console.getvalue()

    def assert_refused(self, path: Path, *words: str, public_key: str | None = None) -> export.VerifyReport:
        """verify fails, naming ``words``; the CLI exits 1 with the result and no traceback or terminal control."""
        report = export.verify_archive(path, public_key=public_key)
        self.assert_fails(report, *words)
        argv = ["verify", str(path)] + (["--public-key", public_key] if public_key is not None else [])
        code, said = self.run_cli(*argv)
        self.assertEqual(code, 1, said)
        self.assertIn("Result:     FAILED", said)
        self.assertNotIn("Traceback", said)
        self.assertTrue(no_terminal_control(said), repr(said))
        return report

    def assert_passes(self, path: Path) -> export.VerifyReport:
        report = export.verify_archive(path)
        self.assertTrue(report.ok, "\n".join(report.problems))
        return report


class ANameHeldTwiceFails(HandBuiltArchives):
    def test_a_file_held_twice_fails_and_every_check_reads_the_copy_that_is_unpacked_last(self):
        self.assert_refused(self.archive(self.entries(extra=[regular(VERSION, b"changed\n")])),
                            f"{VERSION} appears 2 times", f"tampered: {VERSION}")

        def other_estate(_members, document):
            document["estate"] = "other"

        true_one = self.entries(signed=True)
        forged = data_of(self.entries(other_estate), DOCUMENT)
        # A forged export manifest after the true one: tar leaves the last
        # on disk, and the summary, the hashes and the signature all read
        # it, so the signature made over the first does not verify it.
        self.assert_refused(self.archive(true_one + [regular(DOCUMENT, forged)]), f"{DOCUMENT} appears 2 times",
                            "export-manifest.json says estate is 'other', but manifest.json says 'fixture'",
                            "does not verify", public_key=self.key_line)
        # Signed over the forged one, with the true one last: still refused.
        self.assert_refused(
            self.archive(self.entries(other_estate, signed=True) + [regular(DOCUMENT, data_of(true_one, DOCUMENT))]),
            f"{DOCUMENT} appears 2 times", "does not verify", public_key=self.key_line,
        )


class NamesNoExportWritesFail(HandBuiltArchives):
    def test_each_odd_name_fails_with_its_problem(self):
        long_name = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/{'show_' * 60}version.txt"
        case_twin = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/SHOW_VERSION.txt"

        # Each listed in the export manifest with its true hash, so that only
        # the name is wrong.
        cases = {
            "a ./ copy of a member": ([regular(f"./{VERSION}", b"changed\n")], tarfile.PAX_FORMAT,
                                      "is outside the archive's folder"),
            "a trailing slash": ([regular(f"{VERSION}/", b"x\n")], tarfile.PAX_FORMAT, "is not a file an export holds"),
            "a NUL in a pax name": ([with_pax(CLOCK, b"x\n", path=f"{VERSION}\0.txt")], tarfile.PAX_FORMAT,
                                    "has a control character"),
            "an escape in a name": ([regular(CLOCK.replace("clock", "clock\x1b[2K"), b"x\n")], tarfile.PAX_FORMAT,
                                    "has a control character"),
            "a GNU long name": ([regular(long_name, b"x\n")], tarfile.GNU_FORMAT, "manifest.json names no such file"),
            "a pax long name": ([regular(long_name, b"x\n")], tarfile.PAX_FORMAT, "manifest.json names no such file"),
            "a plausible file": ([regular(CLOCK, b"12:00:00 UTC\n")], tarfile.PAX_FORMAT,
                                 f"extra: {CLOCK} is in the archive, but manifest.json"),
            "a name another's but for case": ([regular(case_twin, b"x\n")], tarfile.PAX_FORMAT,
                                              "manifest.json names no such file"),
            "a top file but for case": ([regular(f"{SNAPSHOT_ID}/Manifest.json", b"{}\n")], tarfile.PAX_FORMAT,
                                        "is not a file an export holds"),
        }
        for label, (extra, form, words) in cases.items():
            with self.subTest(label):
                self.assert_refused(self.archive(self.entries(listing(*extra), extra), form), words)

    def test_the_estates_own_files_are_refused_as_what_they_are(self):
        # The shape rule would refuse them anyway; the refusal says what
        # leaked, which is what the owner must tell the prospect.
        for name, words in (("lifecycle.yaml", "the estate's lifecycle data (lifecycle.yaml)"),
                            ("docmeta.yaml", "the estate's document metadata (docmeta.yaml)"),
                            ("rbt-ald-pe1/known_hosts", "the estate's pinned host keys (known_hosts)"),
                            (".env", "a credentials file (.env)")):
            with self.subTest(name=name):
                extra = [regular(f"{SNAPSHOT_ID}/{name}", b"# made by hand\n")]
                self.assert_refused(self.archive(self.entries(listing(*extra), extra)),
                                    f"{SNAPSHOT_ID}/{name} is {words}, which an export never carries")

    def test_an_archive_with_no_export_manifest_where_export_puts_it_fails(self):
        # Without it there is no list to hold the members to, and every
        # other check of the archive reads it: its absence is the problem.
        for label, entries in (
            ("left out", [(info, data) for info, data in self.entries() if info.name != DOCUMENT]),
            ("a folder down", [(info, data) for info, data in self.entries()
                               if info.name != DOCUMENT] + [regular(f"{SNAPSHOT_ID}/rbt-ald-pe1/export-manifest.json",
                                                                    data_of(self.entries(), DOCUMENT))]),
        ):
            with self.subTest(label):
                self.assert_refused(self.archive(entries), "the archive holds no export-manifest.json")

    def test_a_manifest_json_naming_a_file_outside_the_snapshot_fails(self):
        # DiscoNet reads a run's files where its manifest says they are, so
        # an unpacked archive whose manifest names `../` reads outside it.
        for named, words in (("../../outside.txt", "climbs out of the snapshot"),
                             ("/etc/hostname", "is an absolute path")):
            with self.subTest(named=named):
                def change(members, document):
                    manifest = json.loads(members[MANIFEST])
                    manifest["devices"]["rbt-ald-pe1"]["commands"][0]["raw_file"] = named
                    members[MANIFEST] = json.dumps(manifest).encode("utf-8")
                    members.pop(VERSION)
                    document["files"].pop(VERSION)
                    listed(document, MANIFEST, members[MANIFEST])

                self.assert_refused(self.archive(self.entries(change)),
                                    f"manifest.json names {named!r} for rbt-ald-pe1's 'show version', which {words}")

    def test_a_top_file_left_out_of_the_file_list_fails_as_extra_however_little_it_changed(self):
        # Nothing else holds manifest.json or testbed.yaml to bytes: a
        # change that keeps the summary and adds no credential is seen only
        # because the file is not on the list.
        for name in (MANIFEST, f"{SNAPSHOT_ID}/testbed.yaml"):
            with self.subTest(name=name):
                def change(members, document):
                    members[name] = members[name] + b"\n"
                    document["files"].pop(name)

                self.assert_refused(self.archive(self.entries(change)),
                                    f"extra: {name} is in the archive but not listed in the export manifest")

    def test_pax_headers_that_rename_or_resize_a_member_fail(self):
        def without_version(members, _document):
            members.pop(VERSION)

        data = self.members[VERSION]
        cases = {
            "renamed to the database": ([with_pax(VERSION, data, path=f"{SNAPSHOT_ID}/disconet.db")],
                                        ("the estate database", f"missing: {VERSION}")),
            "longer than its data": ([with_pax(VERSION, data, size=str(len(data) + 1024))], ()),
            "shorter than its data": ([with_pax(VERSION, data, size="1")], ()),
        }
        for label, (extra, words) in cases.items():
            with self.subTest(label):
                entries = self.entries(without_version)
                self.assert_refused(self.archive(entries[:1] + extra + entries[1:]), *words)
        # A global header's records apply to every member after it, as tar
        # programs each see fit; export writes none.
        for records in ({"comment": "made by hand"}, {"size": "0"}):
            with self.subTest(records=records):
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT, pax_headers=records) as tar:
                    for info, data in self.entries():
                        tar.addfile(info, io.BytesIO(data))
                self.assert_refused(self.archive(tar=buffer.getvalue()), "holds a global pax header")

    def test_names_that_differ_only_in_case_and_are_both_named_pass_with_a_warning(self):
        # A run on Linux can write both, for two devices whose names differ
        # in case; unpacked on macOS or Windows they are one file.
        twin = "rbt-ald-pe1/raw/SHOW_VERSION.txt"

        def change(members, document):
            manifest = json.loads(members[MANIFEST])
            manifest["devices"]["rbt-ald-pe1"]["commands"].append(
                {"command": "show version twin", "status": "raw", "raw_file": twin, "state_file": None})
            members[MANIFEST] = json.dumps(manifest).encode("utf-8")
            members[f"{SNAPSHOT_ID}/{twin}"] = b"twin\n"
            listed(document, MANIFEST, members[MANIFEST])
            listed(document, f"{SNAPSHOT_ID}/{twin}", b"twin\n")

        report = self.assert_passes(self.archive(self.entries(change)))
        self.assertTrue([w for w in report.warnings if "differ only in case" in w and twin in w], report.warnings)


class EntriesThatAreNoRegularFileFail(HandBuiltArchives):
    def test_pipes_devices_sparse_and_unknown_entries_fail(self):
        sparse_map = b"1\n0\n2\n".ljust(512, b"\0") + b"hi"
        sparse, _data = regular(f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/GNUSparseFile.0/show_clock.txt", sparse_map)
        sparse.pax_headers = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.name": CLOCK,
                              "GNU.sparse.realsize": "2"}
        contiguous, contiguous_data = regular(CLOCK, b"x\n")
        contiguous.type = tarfile.CONTTYPE
        unknown, unknown_data = regular(CLOCK, b"x\n")
        unknown.type = b"V"
        cases = {
            "a FIFO": ((entry(CLOCK, tarfile.FIFOTYPE),), "is a FIFO"),
            "a character device": ((entry(CLOCK, tarfile.CHRTYPE, devmajor=1, devminor=3),), "a character device"),
            "a block device": ((entry(CLOCK, tarfile.BLKTYPE, devmajor=8),), "a block device"),
            "a pax sparse file": (((sparse, sparse_map),), f"{CLOCK} is a sparse file"),
            "a contiguous file": (((contiguous, contiguous_data),), "a contiguous file"),
            "an entry of no type tar knows": (((unknown, unknown_data),), "an entry of type b'V'"),
        }
        for label, (extra, words) in cases.items():
            with self.subTest(label):
                self.assert_refused(self.archive(self.entries(extra=list(extra))), words)


class NothingAfterTheEndGoesUnchecked(HandBuiltArchives):
    def test_a_second_archive_or_any_data_after_the_end_fails(self):
        good = tar_bytes(self.entries())
        hidden = tar_bytes([regular(f"{SNAPSHOT_ID}/.env", b"DISCONET_PASSWORD=x\n")])
        members_only = good.rstrip(b"\0")
        members_only += b"\0" * (-len(members_only) % 512)
        after_end = "holds data after the end of its tar archive"
        damaged = "has a gzip stream that is damaged or cut short after the end of its tar archive"
        compressed = gzip.compress(good, mtime=0)
        cases = {
            # Unpacked by tar --ignore-zeros, and never read by tarfile.
            "a tar after the end blocks": (self.archive(tar=good + hidden), after_end),
            "a second gzip member holding a tar": (self.archive(tar=good, after=gzip.compress(hidden)), after_end),
            "text after the end blocks": (self.archive(tar=good + b"hidden\n"), after_end),
            # tarfile stops, silently, at the first block that is no header.
            "a block of junk where the end begins": (
                self.archive(tar=members_only + b"no header here ".ljust(512, b"x") + b"\0" * 10240), after_end),
            "bytes after the gzip stream": (self.archive(tar=good, after=b"trailing bytes"), damaged),
        }
        # The gzip trailer is the CRC-32, then the size.
        crc = self.out / "crc.export.tar.gz"
        crc.write_bytes(compressed[:-8] + bytes(4) + compressed[-4:])
        cases["a gzip CRC that is wrong"] = (crc, damaged)
        for label, (path, words) in cases.items():
            with self.subTest(label):
                self.assert_refused(path, words)

    def test_zero_padding_passes_and_a_stream_cut_short_is_unreadable(self):
        good = tar_bytes(self.entries())
        self.assert_passes(self.archive(tar=good, after=b"\0" * 1024))
        self.assert_passes(self.archive(tar=good + b"\0" * 20480))
        cut = self.out / "cut.export.tar.gz"
        cut.write_bytes(gzip.compress(good, mtime=0)[: len(gzip.compress(good, mtime=0)) // 2])
        report = export.verify_archive(cut)
        self.assertFalse(report.ok)
        self.assertFalse(report.readable)
        code, said = self.run_cli("verify", str(cut))
        self.assertEqual(code, 2, said)
        self.assertNotIn("Traceback", said)

    def test_the_same_members_in_another_tar_form_pass(self):
        for form in (tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT):
            with self.subTest(form=form):
                self.assert_passes(self.archive(self.entries(signed=True), form))


class JsonNoExportWritesFails(HandBuiltArchives):
    def test_a_key_held_twice_or_one_export_never_writes_fails(self):
        def manifest_says_two_things(members, document):
            members[MANIFEST] = with_key_twice(members[MANIFEST], "estate", "other")
            listed(document, MANIFEST, members[MANIFEST])

        def a_key_of_its_own(_members, document):
            document["approved_by_owner"] = True

        def sized(size: Any) -> Callable[[dict[str, bytes], dict], None]:
            def change(_members, document):
                document["files"][VERSION]["bytes"] = size
            return change

        def hashed(spell: Callable[[str], str]) -> Callable[[dict[str, bytes], dict], None]:
            def change(_members, document):
                document["files"][VERSION]["sha256"] = spell(document["files"][VERSION]["sha256"])
            return change

        twice = with_key_twice(data_of(self.entries(), DOCUMENT), "estate", "other")
        cases = {
            "the export manifest holding a key twice": (
                self.entries(raw_document=twice, signed=False), "the key 'estate' appears twice in one object"),
            "the export manifest holding a key twice, signed as it is": (
                self.entries(raw_document=twice, signed=True), "the key 'estate' appears twice in one object"),
            "manifest.json holding a key twice": (
                self.entries(manifest_says_two_things), "the key 'estate' appears twice in one object"),
            "a key export never writes": (
                self.entries(a_key_of_its_own), "holds 'approved_by_owner', which export does not write"),
            "a size that is a float": (self.entries(sized(float(len(self.members[VERSION])))), f"tampered: {VERSION}"),
            "a size that is a string": (self.entries(sized(str(len(self.members[VERSION])))), f"tampered: {VERSION}"),
            "a size that is negative": (self.entries(sized(-1)), f"tampered: {VERSION}"),
            "a hash in capitals": (self.entries(hashed(str.upper)), f"tampered: {VERSION}"),
            "a hash that is no hex": (self.entries(hashed(lambda text: "z" * 64)), f"tampered: {VERSION}"),
            "a file list that is a list": (self.entries(lambda _m, document: document.update(
                files=sorted(document["files"]))), "the export manifest lists no files"),
            # NaN is no JSON, but Python reads and writes it: it equals no
            # count, so the summary verify derives differs from it.
            "a count that is NaN": (self.entries(raw_document=data_of(self.entries(), DOCUMENT).replace(
                b'"device_count": 3', b'"device_count": NaN')), "says device_count is NaN"),
        }
        for label, (entries, words) in cases.items():
            with self.subTest(label):
                self.assert_refused(self.archive(entries), words)

    def test_a_signature_file_holding_more_than_export_writes_fails(self):
        signed = self.entries(signed=True)
        signature = json.loads(signed[-1][1])
        cases = {
            "a key of its own": (json.dumps({**signature, "note": "anything"}).encode(), "holds the keys"),
            "a key held twice": (with_key_twice(json.dumps(signature).encode(), "alg", "rsa"), "appears twice"),
            "another algorithm": (json.dumps({**signature, "alg": "rsa"}).encode(), "'rsa', not 'ed25519'"),
        }
        for label, (data, words) in cases.items():
            for key in (self.key_line, None):
                with self.subTest(label, key_given=key is not None):
                    entries = signed[:-1] + [regular(SIGNATURE, data)]
                    self.assert_refused(self.archive(entries), "the signature cannot be checked", words,
                                        public_key=key)

    def test_an_export_manifest_or_manifest_json_too_large_to_read_fails(self):
        for limit in (len(self.members[DOCUMENT]) - 1, len(self.members[MANIFEST]) - 1):
            with self.subTest(limit=limit), mock.patch.object(export, "KEEP_LIMIT", limit):
                self.assert_refused(self.good, "is too large for verify to read")


class TheKeyAskedForIsCompared(HandBuiltArchives):
    def test_an_empty_public_key_fails_rather_than_leave_the_key_uncompared(self):
        for given in ("", "   "):
            with self.subTest(given=given):
                report = self.assert_refused(self.good, "the --public-key given is empty", public_key=given)
                self.assertFalse(report.summary["signature"]["compared"])

    def test_a_signature_with_no_export_manifest_it_can_be_checked_against_says_so(self):
        signed = [(info, data) for info, data in self.entries(signed=True) if info.name != DOCUMENT]
        self.assert_refused(self.archive(signed), "the signature cannot be checked: the export manifest or the "
                                                  "signature is unreadable", public_key=self.key_line)

    def test_a_key_line_that_is_malformed_or_names_another_key_id_fails(self):
        alg, kid, key = self.key_line.split()
        for given, words in ((f"{alg} {kid} {key[:-2]}", "is not base64"),
                             (f"{alg} {'0' * len(kid)} {key}", "the line was altered"),
                             (f"{self.key_line} trailing", "is one line of the form")):
            with self.subTest(given=given):
                report = self.assert_refused(self.good, "the --public-key given cannot be used", words,
                                             public_key=given)
                self.assertFalse(report.summary["signature"]["compared"])
        # The same line in a file, with a note beside it, is compared.
        saved = self.base / "sender.pub"
        saved.write_text(f"# read out by phone\n{self.key_line}\n", encoding="utf-8")
        report = export.verify_archive(self.good, public_key=str(saved))
        self.assertTrue(report.ok, report.problems)
        self.assertTrue(report.summary["signature"]["compared"])


class ExportRefusesWhatVerifyWould(ExportFixture):
    def test_a_manifest_holding_a_key_twice_or_naming_a_file_with_a_control_character_is_refused(self):
        path = self.snapshot / "manifest.json"
        as_written = path.read_bytes()
        for label, data, words in (
            ("a key twice", with_key_twice(as_written, "estate", "other"), "the key 'estate' appears twice"),
            ("an escape in a file name", as_written.replace(b'"rbt-ald-pe1/raw/show_version.txt"',
                                                             b'"rbt-ald-pe1/raw/show\\u001b_version.txt"'),
             "has a control character"),
        ):
            with self.subTest(label):
                path.write_bytes(data)
                with self.assertRaises(export.ExportRefused) as caught:
                    self.exported()
                self.assertIn(words, str(caught.exception))
                self.assertEqual(list(self.out.iterdir()), [])
        path.write_bytes(as_written)


class FilesNamedAcrossDevicesAreTheManifestsToSay(ExportFixture):
    def test_a_file_named_under_another_devices_folder_or_for_two_devices_exports_once_and_verifies(self):
        # Which device a file is for is manifest.json's statement, and the
        # archive holds exactly the files it names: there is nothing in the
        # archive for verify to find changed, so it passes, the file once.
        shared = "rbt-bht-p2/raw/show_version.txt"
        for label, device in (("another device's folder", "rbt-ald-pe1"), ("two devices, one file", "rbt-bht-rr2")):
            with self.subTest(label):
                self.rewrite_manifest(lambda manifest: manifest["devices"][device]["commands"][0].update(
                    raw_file=shared))
                result = self.exported(f"{device}.export.tar.gz")
                report = export.verify_archive(result.path)
                self.assertTrue(report.ok, report.problems)
                self.assertEqual(list(contents(result.path)).count(f"{SNAPSHOT_ID}/{shared}"), 1)


class WhatVerifyPrintsIsPlainText(ExportFixture):
    def test_names_from_the_archive_cannot_move_the_cursor_or_forge_a_result_line(self):
        forged = "fixture\x1b[2K\x1b[1A\nResult:     OK‮"
        self.rewrite_manifest(lambda manifest: manifest.update(estate=forged))
        result = self.exported()
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)
        lines = export.summary_lines(report)
        self.assertTrue(all(no_terminal_control(line) for line in lines), lines)
        self.assertIn("(estate fixture\\x1b[2K\\x1b[1A\\nResult:     OK\\u202e)", "\n".join(lines))
        console = io.StringIO()
        with redirect_stdout(console):
            code = cli.main(["verify", str(result.path)])
        said = console.getvalue()
        self.assertEqual(code, 0, said)
        self.assertTrue(no_terminal_control(said), repr(said))
        self.assertEqual([line for line in said.splitlines() if line.startswith("Result:")], ["Result:     OK"])


if __name__ == "__main__":
    unittest.main()
