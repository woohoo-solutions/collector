"""WS3: the command line around `disconet export` and `disconet verify`.

test_collector_export holds the archive to its rules through the engine;
this file holds what the CLI adds on top of it, each a case the review of
WS3 found reaching the operator wrongly:

* an estate named by --estate or DISCONET_ESTATE filled in --testbed, and
  export packed that estate's testbed as the run's own for a snapshot
  another estate collected, so one network's device names, addresses and
  usernames went out labelled as another's;
* verify's help offered --estate, --db and --base-dir, which it ignores;
* a summary that raised, and an I/O failure the engine did not turn into a
  refusal, reached the operator as a traceback;
* every warning the engine returns is printed, whatever it says.

The fixture is test_collector_export's hand-written estate of three demo
devices, beside a second estate, "harbour", whose testbed holds another
demo device at a documentation address. Nothing here names a real network.
"""

from __future__ import annotations

import dataclasses
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


from netstate import cli
from tests.test_collector_export import (
    EXPORTED_AT, SNAPSHOT_ID, build_estate, contents, regular, write_archive,
)
from netstate import export

# The second estate's testbed: a device of the demo's naming at a
# documentation address, and a marker that says which testbed an archive
# carries, since the fixture's own never holds it.
OTHER_MARKER = "harbour-testbed-marker"
OTHER_TESTBED = f"""\
testbed:
  name: {OTHER_MARKER}
devices:
  rbt-hrb-ce2:
    os: iosxe
    type: router
    credentials:
      default:
        username: harbourops
        password: "%ENV{{DISCONET_PASSWORD}}"
    connections:
      cli:
        protocol: ssh
        ip: 203.0.113.99
"""


class CommandLineFixture(unittest.TestCase):
    """The fixture estate, a second estate beside it, an empty output folder, and HOME and DISCONET_ESTATE held."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.estate, self.snapshot = build_estate(self.base)
        self.testbed = self.estate / "testbed.yaml"
        self.other = self.base / "harbour"
        self.other.mkdir()
        (self.other / "testbed.yaml").write_text(OTHER_TESTBED, encoding="utf-8")
        self.out = self.base / "out"
        self.out.mkdir()
        self.home = self.base / "home"
        self.home.mkdir()
        # patch.dict puts the whole environment back when it stops, so what
        # an estate's .env loads during a test leaves with it.
        environment = mock.patch.dict(os.environ, {"HOME": str(self.home), "DISCONET_ESTATE": ""})
        environment.start()
        self.addCleanup(environment.stop)

    def run_cli(self, *argv: str) -> tuple[int, str]:
        # Wide enough that no path or message is wrapped across lines.
        console = io.StringIO()
        with redirect_stdout(console):
            code = cli.main(list(argv))
        return code, console.getvalue()

    def archive(self, name: str = "cli.export.tar.gz") -> Path:
        return self.out / name

    def assert_nothing_written(self, said: str) -> None:
        self.assertIn("Export refused", said)
        self.assertIn("Nothing was written", said)
        self.assertEqual(list(self.out.iterdir()), [], said)
        self.assertEqual(sorted(path.name for path in self.snapshot.parent.glob("*.export.tar.gz")), [])
        # Refused before the engine is reached, so --sign made no key either.
        self.assertFalse((self.home / ".config").exists(), said)

    def archived_testbed(self, archive: Path) -> str:
        return contents(archive)[f"{SNAPSHOT_ID}/testbed.yaml"].decode("utf-8")


class NoTracebackReachesTheOperator(CommandLineFixture):
    """A summary that raises, and an I/O error the engine let through, are said as a result."""

    def exported(self) -> Path:
        return export.export_snapshot(self.snapshot, testbed=self.testbed, output=self.archive(),
                                      exported_at=EXPORTED_AT).path

    def test_a_summary_that_raises_fails_the_archive_with_exit_1(self):
        archive = self.exported()
        with mock.patch.object(export, "summary_lines", side_effect=TypeError("object of type 'int' has no len()")):
            code, said = self.run_cli("verify", str(archive))
        self.assertEqual(code, 1, said)
        self.assertIn("Result: FAILED (the summary could not be printed: TypeError)", said)
        self.assertNotIn("Traceback", said)
        self.assertNotIn("Result:     OK", said)

    def test_a_summary_that_raises_still_shows_the_problems_found(self):
        archive = self.exported()
        broken = self.archive("broken.export.tar.gz")
        members = contents(archive)
        target = f"{SNAPSHOT_ID}/rbt-ald-pe1/raw/show_version.txt"
        members[target] = b"changed\n"
        write_archive(broken, [regular(name, data) for name, data in members.items()])
        with mock.patch.object(export, "summary_lines", side_effect=AttributeError("no items")):
            code, said = self.run_cli("verify", str(broken))
        self.assertEqual(code, 1, said)
        self.assertIn(target, said)
        self.assertIn("(the summary could not be printed: AttributeError)", said)

    def test_a_summary_that_raises_for_an_unreadable_file_keeps_exit_2(self):
        with mock.patch.object(export, "summary_lines", side_effect=ValueError("bad")):
            code, said = self.run_cli("verify", str(self.archive("absent.export.tar.gz")))
        self.assertEqual(code, 2, said)
        self.assertIn("(the summary could not be printed: ValueError)", said)

    def test_an_os_error_from_the_engine_is_a_refusal_with_exit_2(self):
        failure = FileNotFoundError(2, "No such file or directory", "rbt-ald-pe1/state/show_version.json")
        with mock.patch.object(export, "export_snapshot", side_effect=failure):
            code, said = self.run_cli("export", "--snapshot", str(self.snapshot), "--testbed", str(self.testbed),
                                      "--output", str(self.archive()))
        self.assertEqual(code, 2, said)
        self.assertIn("Export refused:", said)
        self.assertIn("No such file or directory", said)
        self.assertIn("Nothing was written", said)
        self.assertNotIn("Traceback", said)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_an_os_error_while_the_archive_is_packed_leaves_no_file_behind(self):
        # A failure inside the packing itself, past the engine's own
        # conversion of the race it expects: the temporary file goes, and
        # the CLI says it was refused.
        with mock.patch.object(export.gzip, "GzipFile", side_effect=PermissionError(13, "Permission denied")):
            code, said = self.run_cli("export", "--snapshot", str(self.snapshot), "--testbed", str(self.testbed),
                                      "--output", str(self.archive()))
        self.assertEqual(code, 2, said)
        self.assertIn("Permission denied", said)
        self.assertIn("Nothing was written", said)
        self.assertEqual(list(self.out.iterdir()), [])


class EveryWarningTheEngineReturnsIsPrinted(CommandLineFixture):
    def test_each_warning_is_printed_once_as_a_note_and_literally(self):
        warnings = [
            "the testbed may belong to another network: it names none of this run's 3 devices",
            "the testbed holds markup that could not be resolved: %{testbed.custom.missing}",
            "a value written as [bold]markup[/bold] is printed as it is",
        ]
        real = export.export_snapshot

        def with_warnings(*args, **kwargs):
            return dataclasses.replace(real(*args, **kwargs), warnings=list(warnings))

        with mock.patch.object(export, "export_snapshot", side_effect=with_warnings):
            code, said = self.run_cli("export", "--snapshot", str(self.snapshot), "--testbed", str(self.testbed),
                                      "--output", str(self.archive()))
        self.assertEqual(code, 0, said)
        notes = [line.strip() for line in said.splitlines() if line.strip().startswith("Note:")]
        self.assertEqual(len(notes), len(warnings), said)
        for warning, note in zip(warnings, notes):
            self.assertTrue(note.endswith(warning), (note, warning))


if __name__ == "__main__":
    unittest.main()
