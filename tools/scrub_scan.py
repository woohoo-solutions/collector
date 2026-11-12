#!/usr/bin/env python3
"""Fail on any private term in a git repository: every tracked file and the whole history.

    python tools/scrub_scan.py TERMS_FILE [--repo PATH] [--strict]

TERMS_FILE is a JSON list. Each entry is a regular expression, or a pair
[regex, replacement] (the replacement is ignored here), which is the format
of DiscoNet's ~/.config/disconet/scrub_terms.json. A file that is not JSON is
read as one literal term per line, blank lines and lines starting with # left
out. Every term is matched regardless of case.

What is read:
  * every tracked file as it is in the working tree;
  * every object in the repository's object database, whether or not a ref
    reaches it: each blob's text (gzip and zip members unpacked), each tree's
    file names, each commit's message, author and committer, and each tag's
    message.

A hit is reported by where it is and the number of the rule that matched
(0 is the list's first entry), never by the text matched, so the output can
be shared without repeating what it guards against.

One exemption, which --strict removes: a match that is wholly an address the
repository's own hygiene gate allows is counted as allowed, not as a hit:
documentation space, an address of no network, one of the named textbook
private examples in tests/test_hygiene.py, a private block named whole
(172.16.0.0/12), the public resolvers 1.1.1.1 and 8.8.8.8, and a dotted
number that is no address (an octet over 255, part of a five-part release, a
package's ==version). A term list with a rule for every IPv4 address would
otherwise fail on 192.0.2.1. Any other address, private ones included, is a
hit.

Exit status: 0 when nothing was found, 1 when anything was, 2 when the scan
could not run (no terms file, a rule that does not compile, not a git
repository, a terms file inside the repository).

Uses only the standard library and the git command.
"""

from __future__ import annotations

import argparse
import gzip
import io
import ipaddress
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

# The addresses the hygiene gate allows anywhere in the repository. Kept in
# step with tests/test_hygiene.py, which tests that the two lists agree.
ALLOWED_V4_BLOCKS = tuple(ipaddress.ip_network(block) for block in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8", "240.0.0.0/4",
    "128.0.0.0/16",
))
ALLOWED_V6_BLOCKS = tuple(ipaddress.ip_network(block) for block in (
    "2001:db8::/32", "::1/128", "::/128", "fe80::/10", "ff00::/8",
))
TEXTBOOK_PRIVATE = frozenset(
    ipaddress.IPv4Address(f"{network}.{host}")
    for network, hosts in (
        ("10.0.0", (0, 1, 2, 4, 5, 6, 7, 9, 11, 12)),
        ("10.0.12", (0, 1, 2, 3, 10)),
        ("10.1.0", (0, 1, 2, 10, 11, 12, 13, 20, 30, 40, 50, 60, 99, 100, 111)),
        ("10.1.1", (1, 2, 3)),
        ("10.2.0", (0, 7, 11)),
        ("10.10.10", (0, 1, 2, 3, 4, 5, 50, 100, 200, 254)),
        ("10.10.20", (0, 1)),
        ("10.20.30", (40,)),
        ("10.255.0", (1, 2, 3, 4)),
    )
    for host in hosts
)
ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"
MAX_UNPACKED = 64 * 1024 * 1024


class ScanError(Exception):
    """The scan could not run; exit 2."""


@dataclass
class Result:
    hits: list[tuple[str, int]] = field(default_factory=list)   # (where, rule number)
    allowed: Counter = field(default_factory=Counter)            # rule number -> allowed address matches
    files: int = 0
    objects: int = 0

    @property
    def clean(self) -> bool:
        return not self.hits


def load_rules(path: Path) -> list[re.Pattern]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScanError(f"cannot read the terms file: {exc.strerror or exc}") from exc
    try:
        entries = json.loads(raw)
    except ValueError:
        entries = [re.escape(line.strip()) for line in raw.splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
    if not isinstance(entries, list):
        raise ScanError("the terms file is JSON but not a list")
    rules = []
    for number, entry in enumerate(entries):
        pattern = entry[0] if isinstance(entry, (list, tuple)) and entry else entry
        if not isinstance(pattern, str) or not pattern:
            raise ScanError(f"rule {number} is not a non-empty string or [regex, replacement] pair")
        try:
            rules.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise ScanError(f"rule {number} does not compile: {exc}") from exc
    if not rules:
        raise ScanError("the terms file holds no rule")
    return rules


# Named whole, a private block is no one's network; nor are the public
# resolvers a fixture may name as a DNS or NTP server (the gate allows both).
WHOLE_PRIVATE_BLOCKS = tuple(ipaddress.ip_network(block) for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
PUBLIC_RESOLVERS = frozenset(ipaddress.ip_address(a) for a in ("1.1.1.1", "8.8.8.8"))
DOTTED_QUAD = re.compile(r"\d{1,3}(?:[._]\d{1,3}){2}[._](?:\d{1,3}|[xX])(?:/\d{1,3})?")
PREFIX_AFTER = re.compile(r"/\d{1,3}(?!\d)")
PIN = re.compile(r"==\S*$")


def allowed_address(text: str) -> bool:
    """Whether ``text`` is wholly an address or a.b.c.x block that the hygiene gate allows,
    or a dotted quad that no address can have (an octet over 255)."""
    text = text.strip()
    if DOTTED_QUAD.fullmatch(text) and any(int(part) > 255 for part in re.split(r"[._/]", text.split("/")[0])
                                            if part.isdigit()):
        return True
    candidate = re.sub(r"[xX]$", "0", text.replace("_", ".")) if re.fullmatch(
        r"\d{1,3}(?:[._]\d{1,3}){2}[._](?:\d{1,3}|[xX])(?:/\d{1,2})?", text) else text
    # As the gate does, the address as written is judged and its prefix length
    # is not (10.1.1.1/30 is the textbook 10.1.1.1; a /33 is no prefix), except
    # that a private block named whole is allowed.
    written, _, length = candidate.partition("/")
    try:
        address = ipaddress.ip_address(written)
    except ValueError:
        return False
    try:
        network = ipaddress.ip_network(candidate, strict=False) if length else None
    except ValueError:
        network = None
    if address.version == 4:
        if network in WHOLE_PRIVATE_BLOCKS or address in (TEXTBOOK_PRIVATE | PUBLIC_RESOLVERS):
            return True
        return any(address in block for block in ALLOWED_V4_BLOCKS)
    return any(address in block for block in ALLOWED_V6_BLOCKS)


def match_rules(text: str, rules: list[re.Pattern], strict: bool) -> Iterator[tuple[int, int, bool]]:
    """(position, rule number, allowed) of every match."""
    for number, rule in enumerate(rules):
        for match in rule.finditer(text):
            if not match.group(0):
                continue
            yield match.start(), number, (not strict and _allowed_in_place(text, match))


def _allowed_in_place(text: str, match: re.Match) -> bool:
    """allowed_address, reading the match where it stands: a prefix length just
    after it belongs to it; a match inside a longer dotted number (a five-part
    release) or a package pin (name==version) is no address."""
    start, end = match.span()
    if re.match(r"\.\d", text[end:end + 2]) or re.search(r"\d\.$", text[max(0, start - 2):start]):
        return True
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line = text[line_start:line_end if line_end != -1 else len(text)]
    pin = PIN.search(line)
    if pin and line_start + pin.start() < start:
        return True
    prefix = PREFIX_AFTER.match(text, end)
    return allowed_address(match.group(0) + (prefix.group(0) if prefix else ""))


def _texts(data: bytes, depth: int = 0) -> Iterator[tuple[str, str]]:
    """(suffix, text) of a blob, gzip and zip members unpacked."""
    yield "", data.decode("utf-8", errors="replace")
    if depth > 2:
        return
    if data.startswith(GZIP_MAGIC):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as packed:
                inner = packed.read(MAX_UNPACKED)
        except (OSError, EOFError):
            return
        for suffix, text in _texts(inner, depth + 1):
            yield "::gunzip" + suffix, text
    elif data.startswith(ZIP_MAGIC):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as book:
                for member in book.infolist():
                    if member.file_size > MAX_UNPACKED:
                        continue
                    yield f"::{member.filename}", member.filename
                    for suffix, text in _texts(book.read(member), depth + 1):
                        yield f"::{member.filename}{suffix}", text
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return


def _scan(where: str, data: bytes, rules: list[re.Pattern], strict: bool, result: Result) -> None:
    for suffix, text in _texts(data):
        for position, number, allowed in match_rules(text, rules, strict):
            if allowed:
                result.allowed[number] += 1
            else:
                line = text.count("\n", 0, position) + 1
                result.hits.append((f"{where}{suffix}:{line}", number))


def _git(repo: Path, *args: str, data: bytes | None = None) -> bytes:
    ran = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True)
    if ran.returncode != 0:
        raise ScanError(f"git {args[0]} failed: {ran.stderr.decode('utf-8', 'replace').strip()}")
    return ran.stdout


def _objects(repo: Path) -> Iterator[tuple[str, str, bytes]]:
    """(sha, type, contents) of every object in the object database."""
    listing = _git(repo, "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)")
    entries = [line.split() for line in listing.decode().splitlines() if line.strip()]
    if not entries:
        return
    batch = _git(repo, "cat-file", "--batch", data="".join(f"{sha}\n" for sha, _ in entries).encode())
    offset = 0
    for _ in entries:
        end = batch.index(b"\n", offset)
        sha, kind, size = batch[offset:end].decode().split()
        start = end + 1
        yield sha, kind, batch[start:start + int(size)]
        offset = start + int(size) + 1


def _tree_names(data: bytes) -> list[str]:
    names, offset = [], 0
    while offset < len(data):
        space = data.index(b" ", offset)
        nul = data.index(b"\0", space)
        names.append(data[space + 1:nul].decode("utf-8", errors="replace"))
        offset = nul + 21
    return names


def _blob_paths(repo: Path) -> dict[str, str]:
    """A path each reachable blob had, for the report; unreachable blobs have none."""
    paths: dict[str, str] = {}
    listing = _git(repo, "rev-list", "--all", "--reflog", "--objects")
    for line in listing.decode("utf-8", errors="replace").splitlines():
        sha, _, path = line.partition(" ")
        if path:
            paths.setdefault(sha, path)
    return paths


def scan(repo: Path, rules: list[re.Pattern], strict: bool = False) -> Result:
    repo = repo.resolve()
    top = Path(_git(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    result = Result()
    for name in _git(top, "ls-files", "-z").decode("utf-8", errors="replace").split("\0"):
        if not name:
            continue
        path = top / name
        if path.is_file() and not path.is_symlink():
            result.files += 1
            _scan(f"{name} (its path)", name.encode(), rules, strict, result)
            _scan(name, path.read_bytes(), rules, strict, result)
    paths = _blob_paths(top)
    for sha, kind, data in _objects(top):
        result.objects += 1
        short = sha[:12]
        if kind == "blob":
            _scan(f"blob {short} ({paths.get(sha, 'unreachable')})", data, rules, strict, result)
        elif kind == "tree":
            _scan(f"tree {short} file names", "\n".join(_tree_names(data)).encode(), rules, strict, result)
        elif kind in ("commit", "tag"):
            _scan(f"{kind} {short}", data, rules, strict, result)
    return result


def _inside(path: Path, top: Path) -> bool:
    try:
        path.resolve().relative_to(top)
    except ValueError:
        return False
    return True


def main(argv: Iterable[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    parser = argparse.ArgumentParser(prog="scrub_scan", description=__doc__.split("\n\n")[0])
    parser.add_argument("terms", type=Path, help="the terms file (JSON list of regexes or [regex, replacement] pairs)")
    parser.add_argument("--repo", type=Path, default=Path("."), help="the repository to scan (default: here)")
    parser.add_argument("--strict", action="store_true",
                        help="count every match, the addresses the hygiene gate allows included")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        top = Path(_git(args.repo, "rev-parse", "--show-toplevel").decode().strip()).resolve()
        if _inside(args.terms, top):
            raise ScanError("the terms file is inside the repository being scanned; keep it outside, "
                            "or it is one commit away from being published")
        rules = load_rules(args.terms)
        result = scan(top, rules, strict=args.strict)
    except ScanError as exc:
        print(f"scrub_scan: cannot run: {exc}", file=out)
        return 2
    for where, number in result.hits:
        print(f"HIT  {where}: rule {number}", file=out)
    for number, count in sorted(result.allowed.items()):
        print(f"note rule {number}: {count} match(es) were addresses the hygiene gate allows "
              f"(documentation, no-network or textbook examples); --strict counts them", file=out)
    by_rule = Counter(number for _, number in result.hits)
    print(f"Scanned {result.files} tracked file(s) and {result.objects} object(s) with {len(rules)} rule(s): "
          + ("CLEAN" if result.clean else
             f"{len(result.hits)} hit(s), rules {', '.join(str(n) for n in sorted(by_rule))}"), file=out)
    return 0 if result.clean else 1


if __name__ == "__main__":
    sys.exit(main())
