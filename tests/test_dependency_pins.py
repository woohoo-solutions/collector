"""Reproducible installs: bounded ranges, an exact lock, and the release each run used.

pyproject.toml gives each dependency a range from the release the suite last
passed on to the next one that may break it; pyATS, Genie and unicon, which
release together monthly as YY.MM, are held to the one line the read-only
connect was checked on. constraints/ pins the whole resolved set per Python
version, and CI installs with it. Each run records the pyATS, Genie and
unicon releases it connected and parsed with, so a snapshot can be re-read
by the stack that wrote it; a merge keeps each source's and states one at
the top only where every source agrees.

The last class drives unicon's own mock IOS-XE device: the quiet connect is
a claim about unicon's plugin internals, and it is checked here on whatever
unicon is installed, so moving the pin re-checks it.

Public scope: no device, no address, no customer data.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import tomllib
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from netstate import collector
from netstate.collector import PYATS_DISTRIBUTIONS, CommandPolicy, _build_manifest, pyats_versions

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
CONSTRAINTS = {version: ROOT / "constraints" / f"py{version}.txt" for version in ("3.11", "3.12")}
WORKFLOW = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")

# A requirement as pyproject writes one: name, optional [extras], specifiers,
# optional ; marker.
REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*([^;]*?)\s*(;.*)?$")
PYATS_LINE = ("pyats", "genie", "unicon")


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirements() -> dict[str, tuple[str, str]]:
    """{canonical name: (specifier, marker)} for every runtime and optional dependency."""
    lines = list(PYPROJECT["project"]["dependencies"])
    for extra in PYPROJECT["project"].get("optional-dependencies", {}).values():
        lines.extend(extra)
    out = {}
    for line in lines:
        match = REQUIREMENT.match(line)
        assert match, line
        out[canonical(match.group(1))] = (match.group(3).replace(" ", ""), (match.group(4) or "").strip())
    return out


def pins(path: Path) -> dict[str, str]:
    """{canonical name: version} from a constraints file."""
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, version = line.partition("==")
        assert version and not re.search(r"[<>=!~;\s]", version), f"{path.name}: {line!r} is not an exact pin"
        out[canonical(name)] = version
    return out


def release(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version)[:3])


def within(version: str, specifier: str) -> bool:
    """Whether a version satisfies a `>=a,<b` range, the only shape pyproject uses."""
    ok = True
    for clause in specifier.split(","):
        if clause.startswith(">="):
            ok &= release(version) >= release(clause[2:])
        elif clause.startswith("<"):
            ok &= release(version) < release(clause[1:])
        else:
            raise AssertionError(f"unexpected specifier {clause!r}")
    return ok


class EveryDependencyIsBounded(unittest.TestCase):
    def test_every_dependency_but_the_zone_data_has_a_lower_and_an_upper_bound(self):
        for name, (specifier, _marker) in requirements().items():
            if name == "tzdata":
                # Zone data only grows; any newer release is the better one.
                continue
            with self.subTest(name=name):
                self.assertRegex(specifier, r"^>=[0-9.]+,<[0-9.]+$")

    def test_pyats_genie_and_unicon_are_held_to_one_monthly_line_together(self):
        reqs = requirements()
        specifiers = {reqs[name][0] for name in PYATS_LINE}
        self.assertEqual(len(specifiers), 1, specifiers)
        [specifier] = specifiers
        year, month, upper_year, upper_month = map(
            int, re.fullmatch(r">=(\d+)\.(\d+),<(\d+)\.(\d+)", specifier).groups()
        )
        following = (year + 1, 1) if month == 12 else (year, month + 1)
        self.assertEqual((upper_year, upper_month), following)


class TheConstraintsPinTheWholeInstall(unittest.TestCase):
    def test_a_file_per_supported_python_exists_and_says_how_to_regenerate_it(self):
        for version, path in CONSTRAINTS.items():
            with self.subTest(version=version):
                text = path.read_text(encoding="utf-8")
                self.assertIn("tools/lock_dependencies.sh", text)
                self.assertIn(f"pip install -c constraints/py{version}.txt", text)
                self.assertTrue(pins(path))

    def test_every_direct_dependency_is_pinned_inside_its_range(self):
        for version, path in CONSTRAINTS.items():
            pinned = pins(path)
            for name, (specifier, marker) in requirements().items():
                if "win32" in marker:
                    continue  # the lock is of a Linux install
                with self.subTest(python=version, name=name):
                    self.assertIn(name, pinned)
                    if specifier:
                        self.assertTrue(within(pinned[name], specifier), f"{pinned[name]} not in {specifier}")

    def test_the_whole_pyats_family_is_pinned_to_one_release(self):
        for version, path in CONSTRAINTS.items():
            family = {
                name: value for name, value in pins(path).items()
                if name.split("-")[0] in PYATS_LINE
            }
            with self.subTest(python=version):
                self.assertGreaterEqual(len(family), len(PYATS_LINE))
                self.assertEqual(len(set(family.values())), 1, family)

    def test_the_installer_itself_is_not_pinned(self):
        for path in CONSTRAINTS.values():
            self.assertFalse({"pip", "setuptools", "wheel"} & set(pins(path)))

    def test_the_regeneration_script_is_executable(self):
        script = ROOT / "tools" / "lock_dependencies.sh"
        self.assertTrue(script.is_file())
        if os.name != "nt":
            self.assertTrue(os.access(script, os.X_OK))


class CIInstallsFromTheLock(unittest.TestCase):
    def test_the_install_step_uses_the_constraints_for_its_python(self):
        self.assertIn(
            "pip install -c constraints/py${{ matrix.python-version }}.txt -e .", WORKFLOW,
        )

    def test_the_matrix_has_a_constraints_file_for_every_python(self):
        matrix = re.search(r"python-version:\s*\[([^\]]*)\]", WORKFLOW).group(1)
        versions = re.findall(r'"([0-9.]+)"', matrix)
        self.assertEqual(sorted(versions), sorted(CONSTRAINTS))

    def test_the_pip_cache_is_keyed_on_the_constraints_too(self):
        self.assertIn("constraints/py${{ matrix.python-version }}.txt", WORKFLOW.split("cache-dependency-path:")[1])


class TheManifestRecordsThePyatsReleases(unittest.TestCase):
    def build(self):
        with tempfile.TemporaryDirectory() as tmp:
            return _build_manifest(
                Path(tmp) / "20261026T091405Z", datetime(2026, 10, 26, 9, 14, 5, tzinfo=timezone.utc),
                "testbed.yaml", CommandPolicy({"iosxe": {"parse": ["show version"]}}), [], [], 90, 120,
            )

    def test_the_manifest_names_each_distribution_beside_netstate_s_version(self):
        manifest = self.build()
        self.assertEqual(set(manifest["pyats_versions"]), set(PYATS_DISTRIBUTIONS))
        self.assertTrue({"pyats", "genie", "unicon"} <= set(PYATS_DISTRIBUTIONS))
        keys = list(manifest)
        self.assertEqual(keys.index("pyats_versions"), keys.index("netstate_version") + 1)

    def test_the_versions_are_what_is_installed(self):
        from importlib import metadata

        versions = self.build()["pyats_versions"]
        for name in PYATS_DISTRIBUTIONS:
            try:
                installed = metadata.version(name)
            except metadata.PackageNotFoundError:
                installed = None
            self.assertEqual(versions[name], installed)

    def test_a_machine_without_pyats_records_none_and_does_not_fail(self):
        from importlib import metadata

        def missing(name):
            raise metadata.PackageNotFoundError(name)

        with mock.patch("importlib.metadata.version", side_effect=missing):
            self.assertEqual(pyats_versions(), {name: None for name in PYATS_DISTRIBUTIONS})

    def test_the_record_survives_json(self):
        manifest = self.build()
        self.assertEqual(json.loads(json.dumps(manifest))["pyats_versions"], manifest["pyats_versions"])


OCT = {"pyats": "26.10", "genie": "26.10", "genie.libs.parser": "26.10", "unicon": "26.10", "unicon.plugins": "26.10"}
NOV = {name: "26.11" for name in OCT}


def _mock_device_cli() -> str | None:
    beside = Path(sys.executable).parent / "mock_device_cli"
    return str(beside) if beside.exists() else shutil.which("mock_device_cli")


try:
    import unicon  # noqa: F401
    HAVE_UNICON = True
except ImportError:
    HAVE_UNICON = False


@unittest.skipUnless(HAVE_UNICON and sys.platform != "win32" and _mock_device_cli(), "needs unicon and its mock devices")
class TheInstalledUniconConnectsQuietly(unittest.TestCase):
    """unicon's own mock IOS-XE device, connected the way the collector connects.

    The collector's comment on QUIET_CONNECT_ARGUMENTS says unicon's IOS-XE
    plugin asks `show version | include operating mode` on its own during a
    connect, and that the arguments stop it. That is a fact about one unicon
    release; this checks it on the installed one, so a pin moved without
    re-checking fails here.
    """

    def connect(self, quiet: bool) -> list[str]:
        from unicon import Connection
        from unicon.eal.backend import spawn

        sent: list[str] = []
        original = spawn.RawSpawn.send

        def recording(self_, data, *args, **kwargs):
            sent.append(str(data).rstrip("\r\n"))
            return original(self_, data, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(spawn.RawSpawn, "send", recording):
            connection = Connection(
                hostname="Switch", os="iosxe",
                start=[f"{_mock_device_cli()} --os iosxe --state general_enable"],
                # The mock knows `term`, not `terminal`; what matters is that
                # nothing beyond these is sent.
                init_exec_commands=["term length 0", "term width 0"],
                init_config_commands=collector.SESSION_CONFIG_SETUP,
                log_stdout=False, learn_hostname=True, connection_timeout=30,
                logfile=str(Path(tmp) / "unicon.log"),
                **(collector.QUIET_CONNECT_ARGUMENTS if quiet else {}),
            )
            try:
                connection.connect()
            finally:
                connection.disconnect()
        return [line for line in sent if line]

    def test_the_session_config_setup_is_still_empty(self):
        self.assertEqual(collector.SESSION_CONFIG_SETUP, [])

    def test_a_quiet_connect_sends_only_enable_and_the_terminal_setup(self):
        self.assertEqual(set(self.connect(quiet=True)), {"enable", "term length 0", "term width 0"})

    def test_without_the_quiet_arguments_unicon_asks_on_its_own(self):
        # Proves the recording sees what unicon sends: without the arguments
        # the plugin's own question goes out.
        self.assertIn("show version | include operating mode", self.connect(quiet=False))


if __name__ == "__main__":
    unittest.main()
