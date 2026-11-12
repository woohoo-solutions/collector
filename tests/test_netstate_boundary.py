"""The collection engine stands alone: netstate imports nothing above it.

A second product (Flight Recorder) is to import the engine without DiscoNet.
That holds only while no line of netstate names a consumer, and the three
tests here are what keeps it holding: a source scan, a fresh interpreter in
which DiscoNet cannot be imported, and the allowlist shipping in the engine's
own package.
"""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path

import netstate
from netstate import collector

ENGINE = Path(netstate.__file__).parent
CONSUMER_IMPORT = re.compile(r"^\s*(from|import)\s+(disconet|rich|anthropic|jinja2|dotenv)\b")


class TheEngineStandsAlone(unittest.TestCase):
    def test_netstate_source_names_no_consumer(self):
        # Late imports inside functions count: this reads every line.
        found = [
            f"{path.name}:{number}: {line.strip()}"
            for path in sorted(ENGINE.glob("*.py"))
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if CONSUMER_IMPORT.match(line)
        ]
        self.assertEqual(found, [])

    def test_netstate_imports_with_disconet_unimportable(self):
        # None in sys.modules makes `import disconet` raise ImportError, in a
        # fresh interpreter, so the proof is at runtime and not by grep.
        script = (
            "import sys; sys.modules['disconet'] = None; import netstate; "
            "netstate.CommandPolicy.load(); print('ok')"
        )
        ran = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, timeout=120,
            cwd=ENGINE.parent,
        )
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertEqual(ran.stdout.strip(), "ok")

    def test_the_allowlist_ships_with_the_engine(self):
        allowlist = collector.DEFAULT_COMMANDS_FILE
        self.assertTrue(allowlist.is_file())
        self.assertEqual(allowlist.parent.resolve(), ENGINE.resolve())


if __name__ == "__main__":
    unittest.main()
