"""netstate's own command line: collect's arguments, exit codes and report, and the README's quick start."""

from __future__ import annotations

import io
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from netstate import cli
from netstate.collector import ALL_FEATURES, CollectionError, CommandNotAllowed

ROOT = Path(__file__).resolve().parents[1]


def manifest(*devices: tuple[str, bool, list[str]], commands_failed: int = 0, **summary) -> dict:
    """A run's manifest: (name, connected, [status of each command])."""
    entries = {
        name: {
            "name": name, "os": "iosxe", "connected": connected,
            "error": None if connected else "connect failed: timeout",
            "connect_log": None if connected else f"{name}/connect.log",
            "commands": [{"command": f"show c{index}", "status": status} for index, status in enumerate(statuses)],
        }
        for name, connected, statuses in devices
    }
    return {
        "snapshot_id": "20261106T120000Z",
        "devices": entries,
        "summary": {
            "devices_total": len(entries),
            "devices_connected": sum(1 for _, connected, _ in devices if connected),
            "commands_failed": commands_failed,
            **summary,
        },
    }


class Collect(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def run_cli(self, *argv: str, returns=None, raises=None) -> tuple[int, str, mock.Mock]:
        fake = mock.Mock(return_value=returns, side_effect=raises)
        out = io.StringIO()
        with mock.patch("netstate.collector.run_collect", fake), redirect_stdout(out):
            code = cli.main(["collect", "--testbed", str(self.base / "testbed.yaml"),
                             "--base-dir", str(self.base / "snapshots"), *argv])
        return code, out.getvalue(), fake

    def test_every_device_answering_is_exit_0_with_a_line_per_device(self):
        code, said, fake = self.run_cli(returns=manifest(("R1", True, ["parsed", "parsed", "raw"]),
                                                         ("R2", True, ["parsed", "empty"])))
        self.assertEqual(code, 0, said)
        rows = [line.split() for line in said.splitlines() if line.strip().startswith(("R1", "R2"))]
        self.assertEqual(rows, [["R1", "iosxe", "yes", "2", "-", "-", "1", "-"],
                                ["R2", "iosxe", "yes", "1", "1", "-", "-", "-"]])
        self.assertIn(f"Snapshot: {self.base / 'snapshots' / '20261106T120000Z'}", said)

    def test_a_short_key_login_and_a_wrong_testbed_are_said_on_the_device_s_row(self):
        run = manifest(("R1", True, ["parsed"]), ("R2", True, ["parsed"]))
        run["devices"]["R1"].update(ssh_client="disconet-ssh", host_key_bits=512)
        run["devices"]["R2"].update(protocol="telnet", declared_os="ios")
        code, said, _ = self.run_cli(returns=run)
        self.assertEqual(code, 0, said)
        [r1] = [line for line in said.splitlines() if line.strip().startswith("R1 ")]
        self.assertIn("logged in through disconet-ssh: OpenSSH refuses this device's RSA host key of 512 bits", r1)
        [r2] = [line for line in said.splitlines() if line.strip().startswith("R2 ")]
        self.assertIn("logged in over telnet", r2)
        self.assertIn("the testbed declares os: ios", r2)

    def test_a_device_that_did_not_answer_is_exit_1_and_none_answering_too(self):
        code, said, _ = self.run_cli(returns=manifest(("R1", True, ["parsed"]), ("R2", False, [])))
        self.assertEqual(code, 1, said)
        self.assertIn("Incomplete: 1 device(s) unreachable", said)
        self.assertIn("R2: SSH dialog in", said)
        code, said, _ = self.run_cli(returns=manifest(("R1", False, [])))
        self.assertEqual(code, 1, said)
        self.assertIn("No device was reachable", said)

    def test_a_refused_command_or_a_failed_collection_is_exit_2(self):
        code, said, _ = self.run_cli(raises=CommandNotAllowed("configure terminal is not a show command"))
        self.assertEqual(code, 2)
        self.assertIn("Refused: configure terminal", said)
        code, said, _ = self.run_cli(raises=CollectionError("testbed not found"))
        self.assertEqual(code, 2)
        self.assertIn("Collection failed: testbed not found", said)

    def test_an_allowlist_that_will_not_load_stops_before_any_collection(self):
        bad = self.base / "commands.yaml"
        bad.write_text("iosxe:\n  parse:\n    - configure terminal\n", encoding="utf-8")
        code, said, fake = self.run_cli("--commands", str(bad))
        self.assertEqual(code, 2, said)
        self.assertIn("Refused: the allowlist did not load", said)
        fake.assert_not_called()
        bad.write_text("iosxe: [unclosed\n", encoding="utf-8")
        code, said, fake = self.run_cli("--commands", str(bad))
        self.assertEqual(code, 2, said)
        self.assertIn("Refused: the allowlist did not load", said)
        fake.assert_not_called()

    def test_the_opt_ins_are_off_unless_given_and_reach_the_engine_as_given(self):
        _, _, fake = self.run_cli(returns=manifest(("R1", True, ["parsed"])))
        sent = fake.call_args.kwargs
        for flag in ("allow_legacy_ssh", "allow_telnet", "verify_reachability", "crawl", "session_log", "double_enable"):
            self.assertIs(sent[flag], False, flag)
        self.assertEqual(sent["crawl_scope"], [])
        self.assertEqual(sorted(sent["features"]), sorted(ALL_FEATURES))
        _, _, fake = self.run_cli("--allow-legacy-ssh", "--allow-telnet", "--verify-reachability", "--crawl",
                                  "--crawl-scope", "192.0.2.0/24,198.51.100.0/24", "--crawl-scope", "203.0.113.0/24",
                                  "--features", "none", "--devices", "R1, R2",
                                  returns=manifest(("R1", True, ["parsed"])))
        sent = fake.call_args.kwargs
        for flag in ("allow_legacy_ssh", "allow_telnet", "verify_reachability", "crawl"):
            self.assertIs(sent[flag], True, flag)
        self.assertEqual(sent["crawl_scope"], ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"])
        self.assertEqual(sent["features"], [])
        self.assertEqual(sent["devices"], ["R1", "R2"])

    def test_no_host_key_prompt_without_a_terminal(self):
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False
            _, _, fake = self.run_cli(returns=manifest(("R1", True, ["parsed"])))
        self.assertIsNone(fake.call_args.kwargs["confirm_host_key"])
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = True
            _, _, fake = self.run_cli(returns=manifest(("R1", True, ["parsed"])))
        self.assertIs(fake.call_args.kwargs["confirm_host_key"], cli._confirm_host_key)

    def test_the_host_key_prompt_pins_only_on_an_explicit_yes(self):
        target = mock.Mock(device="R1", pattern="192.0.2.11")
        key = mock.Mock(key_type="ssh-ed25519", fingerprint="SHA256:abc")
        for answer, pinned in (("y\n", True), ("yes\n", True), ("\n", False), ("n\n", False), ("sure\n", False)):
            with mock.patch("sys.stdin", io.StringIO(answer)), redirect_stdout(io.StringIO()) as said:
                self.assertIs(cli._confirm_host_key(target, [key]), pinned, answer)
            self.assertIn("SHA256:abc", said.getvalue())
        with mock.patch("builtins.input", side_effect=EOFError), redirect_stdout(io.StringIO()):
            self.assertFalse(cli._confirm_host_key(target, [key]))

    def test_bad_arguments_are_refused_before_anything_runs(self):
        for argv in (["--features", "isis,bogus"], ["--crawl-scope", "not-a-subnet"], ["--mode", "fuzzy"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stop:
                self.run_cli(*argv)
            self.assertEqual(stop.exception.code, 2)
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as stop:
            cli.main(["collect"])
        self.assertEqual(stop.exception.code, 2)   # --testbed is required

    def test_pyats_missing_is_said_plainly_with_exit_2(self):
        missing = ModuleNotFoundError("No module named 'genie'", name="genie")
        code, said, _ = self.run_cli(raises=missing)
        self.assertEqual(code, 2)
        self.assertIn("pyATS is not installed", said)


class ExportWithNoSnapshotGiven(unittest.TestCase):
    def test_the_newest_by_its_manifest_is_taken_and_none_at_all_is_exit_2(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli.main(["export", "--base-dir", str(base / "none")]), 2)
            self.assertIn("No snapshot given", out.getvalue())
            for name, created in (("b-copy", "2026-11-01T10:00:00+00:00"), ("a-later", "2026-11-02T10:00:00+00:00")):
                (base / name).mkdir()
                (base / name / "manifest.json").write_text(f'{{"created_at": "{created}"}}', encoding="utf-8")
            self.assertEqual(cli._newest_snapshot(base), base / "a-later")


class TheReadmeQuickStart(unittest.TestCase):
    README = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_its_testbed_loads_in_pyats_and_names_only_documentation_addresses(self):
        block = re.search(r"```yaml\n(.*?)```", self.README, re.DOTALL).group(1)
        self.assertNotRegex(block, r"password: (?!\"%ENV)")
        try:
            from genie.testbed import load
        except ImportError:
            self.skipTest("pyATS is not installed")
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(
                "os.environ", {"DISCONET_USERNAME": "u", "DISCONET_PASSWORD": "p", "DISCONET_ENABLE_PASSWORD": "e"}):
            path = Path(folder) / "testbed.yaml"
            path.write_text(block, encoding="utf-8")
            testbed = load(str(path))
        self.assertEqual(sorted(testbed.devices), ["R1", "R2"])
        self.assertEqual({device.os for device in testbed.devices.values()}, {"iosxe", "junos"})

    def test_every_subcommand_and_flag_it_names_exists(self):
        parser = cli.build_parser()
        sub = next(action for action in parser._actions if action.dest == "command")
        for command in re.findall(r"^disconet-collector (\w+)", self.README, re.MULTILINE):
            self.assertIn(command, sub.choices, command)
        known = {flag for choice in sub.choices.values() for action in choice._actions for flag in action.option_strings}
        for flag in set(re.findall(r"`(--[a-z-]+)", self.README)):
            self.assertIn(flag, known | {"--help"}, flag)


class EveryCommandRunsOwnerOnly(unittest.TestCase):
    def test_main_sets_the_umask_to_077_before_anything_runs(self):
        import os

        previous = os.umask(0o022)
        self.addCleanup(os.umask, previous)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["--version"])
        self.assertEqual(os.umask(0o022), 0o077)


class TheShortKeyLoginIsDisclosed(unittest.TestCase):
    """The short-RSA-key login is automatic (owner's decision, 12 Nov 2026).

    The README promises read-only rules and opt-ins; this login is the one
    weaker login on by default, and it also offers legacy algorithms whatever
    --allow-legacy-ssh says. The README must say both, in the words DiscoNet's
    rule 4 and DN-SEC-001 use, and name only algorithms the client offers.
    """

    README = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())

    def test_the_readme_names_it_as_on_by_default_whatever_the_flag_says(self):
        for words in ("One weaker login that is on by default", "under 1024 bits", "`disconet-ssh`",
                      "held to the same pinned host key",
                      "whether or not `--allow-legacy-ssh` is given", "A device behind a jump host is not covered",
                      "It does not govern the short-key login below", "apart from the short-key login"):
            self.assertIn(words, self.README)

    def test_the_algorithms_it_names_are_the_ones_the_client_offers(self):
        from netstate import legacyssh

        said = self.README[self.README.index("One weaker login that is on by default"):]
        said = said[:said.index("A device behind a jump host")]
        self.assertIn("SHA-1 key exchange", said)
        self.assertTrue(any("sha1" in kex for kex in legacyssh.LEGACY_KEX))
        self.assertIn("CBC ciphers", said)
        self.assertTrue(all(cipher.endswith("-cbc") for cipher in legacyssh.LEGACY_CIPHERS))
        for name in ("hmac-md5", "ssh-rsa", "ssh-dss"):
            self.assertIn(f"`{name}`", said)
            self.assertIn(name, legacyssh.LEGACY_MACS + legacyssh.LEGACY_HOST_KEY_ALGS)

    def test_notice_names_asyncssh(self):
        self.assertIn("asyncssh", (ROOT / "NOTICE").read_text(encoding="utf-8"))


class TheCommandIsInstalledAndRunsAsAModule(unittest.TestCase):
    def test_python_m_netstate_prints_the_version(self):
        ran = subprocess.run([sys.executable, "-m", "netstate", "--version"], capture_output=True, text=True,
                             cwd=ROOT, timeout=120)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        from netstate import __version__

        self.assertEqual(ran.stdout.strip(), f"disconet-collector {__version__}")


if __name__ == "__main__":
    unittest.main()
