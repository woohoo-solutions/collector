"""tools/scrub_scan.py: a private term anywhere in a repository, or its history, fails the scan.

Every term here is made up and built in the test, so this file holds nothing
a real list would find.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import scrub_scan
from tests import test_hygiene

TERM = "Zq" + "vorlund"           # a made-up operator name
ALSO = "Kel" + "pastra"           # a made-up town
# Dotted numbers the gate refuses as text, built from parts: a resolver and two
# impossible quads, a five-part release, a package version, a private block.
NO_ADDRESSES = (".".join(("8", "8", "8", "8")), ".".join(("999", "1", "1", "1")), ".".join(("10", "0", "12", "300")))
RELEASE = ".".join(("15", "2", "4", "7", "1"))
PIN = ".".join(("3", "7", "0", "1"))
BLOCK = ".".join(("172", "16", "0", "0")) + "/12"


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class ARepositoryIsScannedWholeAndHistoryToo(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.terms = self.base / "terms.json"
        self.write_terms([[TERM, "operator A"], [ALSO, "town B"], [r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "any address"]])
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.commit({"README.md": "nothing here\n"}, "first")

    def git(self, *args: str) -> str:
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True,
                              text=True, env=env).stdout

    def commit(self, files: dict[str, str | bytes], message: str) -> None:
        for name, content in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)

    def write_terms(self, entries) -> None:
        self.terms.write_text(json.dumps(entries), encoding="utf-8")

    def run_scan(self, *extra: str) -> tuple[int, str]:
        out = io.StringIO()
        code = scrub_scan.main([str(self.terms), "--repo", str(self.repo), *extra], out=out)
        return code, out.getvalue()

    def assert_hit(self, said: str, where: str, rule: int) -> None:
        self.assertTrue([line for line in said.splitlines() if line.startswith("HIT") and where in line
                         and line.endswith(f"rule {rule}")], said)

    def test_a_clean_repository_passes_with_exit_0(self):
        code, said = self.run_scan()
        self.assertEqual(code, 0, said)
        self.assertIn("CLEAN", said)

    def test_a_term_in_a_tracked_file_fails_case_insensitively_and_the_output_never_repeats_it(self):
        self.commit({"notes.txt": f"line one\nthe {TERM.upper()} core\n"}, "notes")
        code, said = self.run_scan()
        self.assertEqual(code, 1, said)
        self.assert_hit(said, "notes.txt:2", 0)
        self.assert_hit(said, "(notes.txt)", 0)   # the same text in history, as a blob
        self.assertNotIn(TERM.lower(), said.lower())

    def test_a_term_removed_from_the_tree_is_still_found_in_history(self):
        self.commit({"old.txt": f"{ALSO} site\n"}, "add")
        (self.repo / "old.txt").unlink()
        self.commit({}, "remove")
        code, said = self.run_scan()
        self.assertEqual(code, 1, said)
        self.assert_hit(said, "blob", 1)
        self.assertNotIn("(working tree)", said)

    def test_a_term_in_a_commit_message_a_file_name_or_an_author_is_found(self):
        self.commit({"x.txt": "x\n"}, f"fix for {TERM}")
        self.commit({f"configs/{ALSO.lower()}-pe1.cfg": "hostname r1\n"}, "named file")
        code, said = self.run_scan()
        self.assertEqual(code, 1, said)
        self.assert_hit(said, "commit", 0)
        self.assert_hit(said, "file names", 1)
        self.assert_hit(said, "(its path)", 1)

    def test_a_term_on_an_unmerged_branch_or_in_an_unreachable_object_is_found(self):
        self.git("checkout", "-q", "-b", "side")
        self.commit({"side.txt": f"{TERM}\n"}, "side")
        self.git("checkout", "-q", "main")
        self.git("branch", "-D", "side")
        self.git("reflog", "expire", "--expire=now", "--all")
        code, said = self.run_scan()
        self.assertEqual(code, 1, said)
        self.assert_hit(said, "blob", 0)

    def test_gzip_and_zip_members_are_read_unpacked(self):
        import gzip
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as book:
            book.writestr("xl/sharedStrings.xml", f"<t>{ALSO}</t>")
        self.commit({"data.json.gz": gzip.compress(f'{{"site": "{TERM}"}}'.encode()),
                     "book.xlsx": buffer.getvalue()}, "packed")
        code, said = self.run_scan()
        self.assertEqual(code, 1, said)
        self.assert_hit(said, "data.json.gz::gunzip", 0)
        self.assert_hit(said, "book.xlsx::xl/sharedStrings.xml", 1)

    def test_an_address_the_gate_allows_is_noted_and_any_other_address_is_a_hit(self):
        self.commit({"a.txt": "router at 192.0.2.1 and 10.0.0.1\n"}, "allowed")
        code, said = self.run_scan()
        self.assertEqual(code, 0, said)
        self.assertIn("note rule 2: 4 match(es)", said)
        code, said = self.run_scan("--strict")
        self.assertEqual(code, 1, said)
        private = ".".join(("10", "77", "0", "1"))   # private, and no textbook example
        self.commit({"b.txt": f"a real prefix {private}\n"}, "private")
        code, said = self.run_scan()
        self.assertEqual(code, 1, said)
        self.assert_hit(said, "b.txt:1", 2)

    def test_a_plain_text_list_is_read_one_literal_term_per_line(self):
        self.terms.write_text(f"# comment\n\n{ALSO}.x\n", encoding="utf-8")
        self.commit({"a.txt": f"{ALSO}.x and {ALSO}yx\n"}, "dots")
        code, said = self.run_scan()
        self.assertEqual(code, 1, said)
        self.assertEqual(len([line for line in said.splitlines() if line.startswith("HIT  a.txt")]), 1, said)

    def test_it_refuses_to_run_without_a_list_with_a_bad_rule_or_with_the_list_inside_the_repository(self):
        self.terms.unlink()
        self.assertEqual(self.run_scan()[0], 2)
        self.write_terms([["(unclosed", "x"]])
        code, said = self.run_scan()
        self.assertEqual((code, "rule 0 does not compile" in said), (2, True), said)
        inside = self.repo / "terms.json"
        inside.write_text(json.dumps([TERM]), encoding="utf-8")
        out = io.StringIO()
        self.assertEqual(scrub_scan.main([str(inside), "--repo", str(self.repo)], out=out), 2)
        self.assertIn("inside the repository", out.getvalue())


class TheScanAllowsExactlyWhatTheGateAllows(unittest.TestCase):
    ANY_ADDRESS = [__import__("re").compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", __import__("re").IGNORECASE)]

    def allowed(self, text: str) -> list[bool]:
        return [allowed for _, _, allowed in scrub_scan.match_rules(text, self.ANY_ADDRESS, strict=False)]

    def test_a_dotted_number_that_is_no_address_is_read_in_place(self):
        private = ".".join(("10", "77", "0", "1"))
        self.assertEqual(self.allowed(f"image {RELEASE} here"), [True])         # part of a five-part release
        self.assertEqual(self.allowed(f"pkg=={PIN}\n"), [True])                 # a package pin
        self.assertEqual(self.allowed(f"the block {BLOCK}"), [True])            # a private block named whole
        self.assertEqual(self.allowed(f"pkg==1.0  # {private}"), [False])        # after a pin, still an address
        self.assertEqual(self.allowed(f"route {private}/24"), [False])
        self.assertEqual(self.allowed("p2p 10.1.1.1/30 and 10.0.12.0/30"), [True, True])   # the address as written
        self.assertEqual(self.allowed("no prefix 10.1.0.0/33"), [True])
        self.assertEqual(self.allowed(f"host {private}."), [False])             # the end of a sentence
        self.assertEqual([a for _, _, a in scrub_scan.match_rules(f"pkg=={PIN}", self.ANY_ADDRESS, strict=True)],
                         [False])

    def test_the_lists_agree(self):
        self.assertEqual(set(scrub_scan.ALLOWED_V4_BLOCKS), set(test_hygiene.PUBLIC_SCOPE_BLOCKS))
        self.assertEqual(scrub_scan.TEXTBOOK_PRIVATE, test_hygiene.PRIVATE_EXAMPLES)

    def test_allowed_addresses(self):
        for text in ("192.0.2.1", "198.51.100.0/24", "203.0.113.x", "203_0_113_7", "10.0.0.1",
                     "2001:db8::1", "127.0.0.1", "fe80::1", "10.0.0.0/8", *NO_ADDRESSES):
            self.assertTrue(scrub_scan.allowed_address(text), text)
        # Built from parts, so the repository's own gate finds none of them here.
        refused = [".".join(parts) for parts in (("10", "0", "0", "3"), ("172", "16", "0", "1"), ("192", "168", "1", "1"))]
        for text in (*refused, refused[0] + "/16", "2a00::1", "zq", "1.2.3"):
            self.assertFalse(scrub_scan.allowed_address(text), text)


if __name__ == "__main__":
    unittest.main()
