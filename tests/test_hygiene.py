"""Nothing that names a real network is in this repository.

Every tracked file is public, and is held to one rule (DiscoNet's release
audit, sections 1 to 3): every IPv4 address is documentation space, an
address of no network, or one of a few named textbook private examples; no
public IPv4 or IPv6 address appears; and every hostname of the shape a real
operator's convention takes is written in the one made-up convention
netstate/naming.py documents. Packed files are read unpacked: a workbook's
cells, gzipped data.

Where the owner's private term list is present ($DISCONET_SCRUB_TERMS, else
~/.config/disconet/scrub_terms.json), every tracked file is searched for
every term in it, case-insensitively; a clone without the list skips that
search. The list never enters the repository, and a term found is reported
by its rule number, never its text. tools/scrub_scan.py runs the same list
over the whole history.
"""

from __future__ import annotations

import ast
import functools
import gzip
import html
import ipaddress
import fnmatch
import json
import os
import re
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]|\.\d)")
IPV4_BLOCK = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){2})\.[xX](?![\w.])")
IPV4_IN_NAME = re.compile(r"(?<![^\W_])\d{1,3}(?:_\d{1,3}){2}_(?:\d{1,3}|[xX])(?![^\W_])")   # dev_a_b_c_d
IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?(?![\w:])")
# A device named role_site_unit: a short upper-case role, underscore segments,
# then a unit number or a letter-digit code. UPPER_SNAKE constants end in a
# word, so they never match. Fixtures use the shape for their made-up
# devices, so it is held against the progress record only.
HOSTNAME = re.compile(r"(?<![\w-])(?:[A-Z]{1,3}-)?[A-Z]{1,4}(?:(?:_[A-Z0-9]{1,10}){1,4}_[A-Z]{0,2}\d{1,2}|_[A-Z]{2,3}\d{1,2})(?![\w-])")
FORMULA = re.compile(r"<f\b[^>]*>[^<]*</f>")
TEXT_NODE = re.compile(r">([^<]+)<")
# Well-known public resolvers a fixture may name as an NTP or DNS server,
# and the space Junos uses internally between its routing engines, which
# is public space on paper and private in every chassis.
ALLOWED = {ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("8.8.8.8")}
ALLOWED_NETWORKS = (ipaddress.ip_network("128.0.0.0/2"),)
SKIP_SUFFIXES = {".svg", ".drawio", ".png", ".jpg", ".ico", ".db"}
PROGRESS = "progress/"


def _tracked_files() -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split("\0")
    return [name for name in listed if name and Path(name).suffix not in SKIP_SUFFIXES]


def _texts(path: Path, name: str):
    """(where, text) of one file. A workbook is read part by part as the
    distinct texts of its XML, formulas left out (they are the builder's
    own); gzipped data is unpacked and read as its distinct lines; JSON,
    and the JSON in a page, is read with its escapes decoded. A text file
    that does not decode is skipped; packed data that does not unpack is an
    error."""
    if path.suffix == ".xlsx":
        with zipfile.ZipFile(path) as book:
            for part in book.namelist():
                if part.endswith(".xml"):
                    xml = FORMULA.sub("", book.read(part).decode("utf-8"))
                    yield f"{name}::{part}", "\n".join(dict.fromkeys(html.unescape(t) for t in TEXT_NODE.findall(xml)))
        return
    packed = path.suffix == ".gz"
    if packed:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            text = fh.read()
    else:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            return
    if path.name.endswith((".json", ".json.gz")):
        try:
            text = json.dumps(json.loads(text), indent=1, ensure_ascii=False)
        except ValueError:
            pass
    if path.suffix == ".html":   # a page's chart data is JSON, a non-ASCII letter in it escaped
        text = re.sub(r"(?:\\u[0-9A-Fa-f]{4})+", lambda m: json.loads(f'"{m.group(0)}"'), text)
    yield name, "\n".join(dict.fromkeys(text.splitlines())) if packed else text


@functools.lru_cache(maxsize=None)
def _corpus() -> tuple[tuple[str, str, str], ...]:
    """(tracked name, where, text) of every tracked file, packed ones unpacked."""
    return tuple((name, where, _without_pins(name, text))
                 for name in _tracked_files() for where, text in _texts(ROOT / name, name))


def _without_pins(name: str, text: str) -> str:
    """A lock file's versions blanked: a four-part release reads as an address."""
    return re.sub(r"(?m)==\S+$", "==", text) if name.startswith("constraints/") else text


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _is_public(address: ipaddress.IPv4Address) -> bool:
    if address in ALLOWED or any(address in net for net in ALLOWED_NETWORKS):
        return False
    return not (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_reserved or address.is_unspecified
    )


def _public_literal(text: str) -> bool | None:
    """Whether an address literal (a.b.c.d or a.b.c.x, IPv6, with or without
    a prefix length) is public space; None when the text is no address. A
    dotted quad that no address can have (an octet over 255, a /33) is not
    public; a MAC address is no address."""
    text = text.strip()
    dotted = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){2}\.)(\d{1,3}|[xX])(/\d{1,3})?", text)
    if dotted:
        text = dotted.group(1) + ("0" if dotted.group(2) in ("x", "X") else dotted.group(2)) + (dotted.group(3) or "")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False if dotted else None
    first = network.network_address
    return _is_public(first) if first.version == 4 else first.is_global and first in ipaddress.ip_network("2000::/3")


def _record_hits(text: str):
    """(position, what) of each device-name shape and public address."""
    for match in HOSTNAME.finditer(text):
        yield match.start(), "device-name shape"
    for pattern, what in ((IPV4, "public IPv4 address"), (IPV4_BLOCK, "public IPv4 block"),
                          (IPV4_IN_NAME, "public IPv4 in a name"), (IPV6, "public IPv6 address")):
        for match in pattern.finditer(text):
            if _public_literal(match.group(0).replace("_", ".")):
                yield match.start(), what


def _terms_path() -> str:
    return os.environ.get("DISCONET_SCRUB_TERMS") or os.path.join(os.path.expanduser("~"), ".config", "disconet", "scrub_terms.json")


def _private_rules() -> list[re.Pattern]:
    """The owner's private terms, a JSON list of [regex, replacement] (or of regexes), matched
    regardless of case; none without the file."""
    path = _terms_path()
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [re.compile(entry[0] if isinstance(entry, list) else entry, re.IGNORECASE) for entry in json.load(fh)]


def _term_hits(name: str, text: str, rules: list[re.Pattern]):
    """(position, rule number) of each private term. The list's address rules
    are the progress record's no-address policy: outside progress/ an
    address it matches counts only when it is public, as everywhere else.
    A block (a.b.c.x) there that a rule taking any block matches does not
    count at all: outside the record that shape is a four-part release as
    often as an address, and no other guard reads blocks there either. A
    rule that names a block of its own still finds it."""
    for number, rule in enumerate(rules):
        any_block = rule.search("192.0.2.x") is not None
        for match in rule.finditer(text):
            if name.startswith(PROGRESS):
                yield match.start(), number
            elif any_block and IPV4_BLOCK.fullmatch(match.group(0)):
                continue
            elif _public_literal(match.group(0)) is not False:
                yield match.start(), number


class NoRealNetworkInTheTree(unittest.TestCase):
    def test_no_public_ipv4_address_is_in_any_tracked_file(self):
        found: list[str] = []
        for _, where, text in _corpus():
            for match in IPV4.finditer(text):
                try:
                    address = ipaddress.ip_address(match.group(1))
                except ValueError:
                    continue
                if _is_public(address):
                    found.append(f"{where}:{_line(text, match.start())}: {match.group(1)}")
        self.assertEqual(found, [], "public addresses in the tree:\n" + "\n".join(found))

    def test_no_private_term_is_in_any_tracked_file(self):
        rules = _private_rules()
        if not rules:
            self.skipTest("no private term list on this machine")
        # The same rule as tools/scrub_scan.py: every match is a hit except an
        # address this gate allows anyway; private addresses are hits.
        from tools.scrub_scan import match_rules

        found = [f"{where}:{_line(text, pos)}: private rule {number}" for name, where, text in _corpus()
                 for pos, number, allowed in match_rules(text, rules, strict=False) if not allowed]
        self.assertEqual(found, [], "private terms in the tree (rule numbers from the list):\n" + "\n".join(found))

    def test_the_guard_recognises_documentation_and_private_space(self):
        # The two RFC 1918 hosts are built from parts, so this file quotes none.
        for text in ("10.0.0.1", ".".join(("172", "16", "1", "1")), ".".join(("192", "168", "1", "1")),
                     "192.0.2.1", "198.51.100.9",
                     "203.0.113.1", "127.0.0.1", "169.254.1.1", "224.0.0.5", "1.1.1.1", "128.0.0.1"):
            self.assertFalse(_is_public(ipaddress.ip_address(text)), text)
        # Built from a number rather than written, so the guard's own file
        # carries no public literal for it to find.
        self.assertTrue(_is_public(ipaddress.ip_address((11 << 24) | 1)))


PUBLIC_V4 = str(ipaddress.IPv4Address((11 << 24) | (2 << 8) | 3))
PUBLIC_V6 = str(ipaddress.IPv6Address((0x2A00 << 112) | 0x10))
DEVICE = "_".join(("PE", "XA", "NORTH", "1"))   # a made-up device of the guarded shape


class TheGuardReadsPackedFilesAndThePrivateList(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_a_workbook_s_cells_and_gzipped_data_are_read(self):
        book = self.dir / "book.xlsx"
        with zipfile.ZipFile(book, "w") as z:
            z.writestr("xl/worksheets/sheet1.xml", f"<row><c><is><t>{DEVICE} at {PUBLIC_V4}, dev_{PUBLIC_V4.replace('.', '_')}</t></is></c>"
                                                   f"<c><f>A1&amp;\"{PUBLIC_V6}\"</f><v></v></c></row>")
            z.writestr("xl/media/image1.png", b"\x89PNG")
        dump = self.dir / "dump.json.gz"
        with gzip.open(dump, "wt", encoding="utf-8") as fh:
            json.dump({"s": [[PUBLIC_V6, "human"], [PUBLIC_V6, "human"]]}, fh)
        texts = dict(_texts(book, "book.xlsx")) | dict(_texts(dump, "dump.json.gz"))
        self.assertEqual(sorted(texts), ["book.xlsx::xl/worksheets/sheet1.xml", "dump.json.gz"])
        self.assertEqual(sorted(what for pos, what in _record_hits(texts["book.xlsx::xl/worksheets/sheet1.xml"])),
                         ["device-name shape", "public IPv4 address", "public IPv4 in a name"])   # the formula is not read
        self.assertEqual([what for pos, what in _record_hits(texts["dump.json.gz"])], ["public IPv6 address"])   # one distinct line
        for private in ("10.0.0.1", "192.0.2.0/24", "2001:db8::1", "203.0.113.x", "fe80::1"):
            self.assertFalse(_public_literal(private), private)
        self.assertTrue(_public_literal(PUBLIC_V4.rsplit(".", 1)[0] + ".x"))
        self.assertFalse(_public_literal("999.1.1.1"))
        self.assertFalse(_public_literal("10.1.0.0/33"))
        self.assertIsNone(_public_literal("12:34:56"))
        self.assertIsNone(_public_literal("00:00:5e:00:53:01"))   # a MAC: a term rule naming one still counts

    def test_a_term_is_reported_by_rule_number_and_a_private_address_only_in_the_record(self):
        rules = [re.compile(r"\bAcmeNet\b"), re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")]
        text = f"AcmeNet core at 10.0.0.1 and {PUBLIC_V4}"
        self.assertEqual([n for _, n in _term_hits("disconet/tests/test_x.py", text, rules)], [0, 1])
        self.assertEqual([n for _, n in _term_hits("progress/README.md", text, rules)], [0, 1, 1])

    def test_a_four_part_version_is_no_address_block_outside_the_record(self):
        """BUG-003: a four-part release ending .x in BUGS.md failed the suite on the record's block rule.

        Its first three parts are public space, so it read as a public block.
        Built from parts, so this file carries no block for the guard to find.
        """
        version = ".".join(("7", "0", "1", "x"))
        block = PUBLIC_V4.rsplit(".", 1)[0] + ".x"
        rules = [re.compile(r"\b\d{1,3}(?:\.\d{1,3}){2}\.[xX]\b"), re.compile(re.escape(block))]
        text = f"release {version}, leaked block {block}"
        self.assertEqual([n for _, n in _term_hits("BUGS.md", text, rules)], [1])
        self.assertEqual([n for _, n in _term_hits("progress/README.md", text, rules)], [0, 0, 1])

    def test_a_page_s_chart_data_is_read_with_its_escapes_decoded(self):
        page = self.dir / "page.html"
        page.write_text("<script>const D=" + json.dumps({"t": "AcméNet core"}) + ";</script>", encoding="utf-8")   # é escaped
        ((where, text),) = _texts(page, "progress/page.html")
        self.assertEqual([n for _, n in _term_hits(where, text, [re.compile("AcméNet")])], [0])

    def test_the_list_is_read_from_the_environment_then_the_home_config_and_may_be_absent(self):
        listed = self.dir / "terms.json"
        listed.write_text(json.dumps([[r"\bAcmeNet\b", "operator A"]]), encoding="utf-8")
        with mock.patch.dict(os.environ, {"DISCONET_SCRUB_TERMS": str(listed)}):
            self.assertEqual([r.pattern for r in _private_rules()], [r"\bAcmeNet\b"])
        with mock.patch.dict(os.environ, {"DISCONET_SCRUB_TERMS": str(self.dir / "absent.json")}):
            self.assertEqual(_private_rules(), [])
        with mock.patch.dict(os.environ, {"HOME": str(self.dir)}):   # restores the whole environment after
            os.environ.pop("DISCONET_SCRUB_TERMS", None)
            self.assertEqual(_terms_path(), str(self.dir / ".config" / "disconet" / "scrub_terms.json"))
            self.assertEqual(_private_rules(), [])


# The whole repository is public, so every tracked file is in the scope.
PUBLIC_SCOPE = ("*",)
# Except the two files that state the rule: this one and the scan that applies
# the same allowed blocks to a private list. Each names the blocks it allows
# and refuses, as DiscoNet's own gate did; every refused example their tests
# use is built from numbers or parts.
GATE_ITSELF = ("tests/test_hygiene.py", "tools/scrub_scan.py")

# The addresses the public scope may quote, whatever the test is about:
# * documentation space (RFC 5737), where every new example comes from;
# * addresses of no network: loopback, link-local, multicast, 0.0.0.0/8 (the
#   unspecified address and wildcard masks) and 240.0.0.0/4 (netmasks and the
#   broadcast address);
# * 128.0.0.0/16, which Junos uses between its routing engines. The audit
#   names Junos's internal block 128.0.0.0/2, but a /2 holds 172.16.0.0/12 and
#   a quarter of public space, so allowing it whole would let through the very
#   addresses a recorded run carries. The internal addresses Junos prints all
#   lie in the block's first /16.
PUBLIC_SCOPE_BLOCKS = tuple(ipaddress.ip_network(block) for block in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8", "240.0.0.0/4",
    "128.0.0.0/16",
))
# The public scope is mostly Python, where a name or an address often stands
# straight behind a string escape ("\nR1#"). The escape's letter is no part
# of it, so the patterns below may start a match there, where the tree-wide
# IPV4 and IPV4_IN_NAME would not.
AFTER_ESCAPE = r"(?<=\\[nrt])"
# An address may end a sentence or a dialog line ("Connected to <address>.",
# "Trying <address>..."), so a full stop on either side ends it. Only a digit
# beside that full stop makes it part of a longer dotted number, such as a
# five-part version. A block written a.b.c.x, dotted or in a name, is read as
# its first address.
NOT_IN_A_LONGER_NUMBER = r"(?:(?<!\w)(?<!\d\.)|" + AFTER_ESCAPE + r")"
PUBLIC_IPV4 = re.compile(NOT_IN_A_LONGER_NUMBER + r"\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\d)")
PUBLIC_IPV4_BLOCK = re.compile(NOT_IN_A_LONGER_NUMBER + r"\d{1,3}(?:\.\d{1,3}){2}\.[xX](?!\w|\.\d)")
PUBLIC_IPV4_IN_NAME = re.compile(
    r"(?:(?<![^\W_])|" + AFTER_ESCAPE + r")\d{1,3}(?:_\d{1,3}){2}_(?:\d{1,3}|[xX])(?![^\W_])"
)
# Private space only as the textbook examples the tests already use as
# ordinary addresses: 10.0.0.1 and its neighbours, the 10.1.0.0/24 the crawl
# tests discover, the 10.10.10.0/24 of the redaction battery, the
# 10.255.0.x loopbacks. The audit found them generic (section 1). They are
# allowed address by address, not as whole /24s: the /24s are the ones real
# networks use most, and a recorded address beside an example would pass
# with its block. The one fixture whose private addresses came from a real run
# used 172.16.0.0/12 and 192.168.0.0/16; it is hand-written now, and nothing in
# either block is allowed. A new test takes its addresses from documentation
# space. One that is about a private address adds that address here, with the
# reason, and a review sees it. Rule 2 of the audit's section 3 still asks
# for this list to shrink.
PRIVATE_EXAMPLES = frozenset(
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

# A hostname in the shape the client's token map kept: role prefix, town code,
# site number, tier letter and unit index (RELEASE-AUDIT.md, "How this was
# checked"). An optional qualifier of up to three letters, a prefix of up to
# four capitals, then any number of underscore segments, of which one carries
# a number, is one of naming's role words (a place and its CORE) or, behind
# the prefix, is a bare two-letter code. It is wider than HOSTNAME above,
# which misses a role letter straight behind the prefix and a name that
# carries no number at all. A name may end in a hyphen, as a file named after
# its device does (<name>-cli.log), and may start behind one.
#
# Two forms stay out of its reach. A longer first word is a constant's
# (DEFAULT_OS), not a role prefix. And two plain words, such as a site type
# before a named site, read exactly like XR_POLICY or SITE_SEPARATOR; those are
# left to the owner's private list and to a review.
NAME_SHAPE = re.compile(r"(?:(?<!\w)|" + AFTER_ESCAPE + r")"
                        r"(?:[A-Z]{1,3}-)?[A-Z]{1,4}(?:_(?:[A-Z]{1,12}\d{0,3}|\d{1,3}))+(?!\w)")
# The same name in lower case, as a directory or a file is named after a
# device (snapshots/<name>/state, /tmp/<name>-cli.log). It is read beside a
# path's slash only: anywhere else, lower case with underscores is a Python
# name. A state file is named after its command, and every command starts
# with show, display or ping, so a name that does is a command's.
LOWER_NAME = r"(?:[a-z]{1,3}-)?[a-z]{1,4}(?:_(?:[a-z]{1,12}\d{0,3}|\d{1,3}))+"
LOWER_NAME_IN_A_PATH = re.compile(r"(?<=/)" + LOWER_NAME + r"(?!\w)|(?<![\w-])" + LOWER_NAME + r"(?=/)")
COMMAND_WORDS = ("show", "display", "ping")
NUMBERED_SEGMENT = re.compile(r"[A-Z]{0,4}\d{1,3}")
TWO_LETTER_SEGMENT = re.compile(r"[A-Z]{2}")
# The one made-up convention a name of that shape may be written in, the one
# documented in netstate/naming.py beside SITE_SEPARATOR; a test below holds
# these lists to that comment. Every segment of such a name is a site type, a
# town with or without its site number, a named site, a role letter and its
# number, an index or one of naming's role words, and only the first may be
# the provider edge's leading role, qualified or bare.
CONVENTION_SITE_TYPES = ("HUB", "POP")
CONVENTION_TOWNS = ("QX", "ZV", "CR")
CONVENTION_SITE_NAMES = ("KESTREL",)
CONVENTION_LEADING_ROLE = "PE"
CONVENTION_QUALIFIERS = ("U",)
# Names of the shape that are no hostname: an interface description the
# redaction tests quote, synthetic by the audit's own reading (section 1), and
# the MACsec and IPsec cipher names (AES_256_CMAC), whose number is a key
# length.
NOT_HOSTNAMES = frozenset({"_".join(("CORE", "LINK", "TO", "R2")),
                           # test_legacyssh's 512-bit host keys, and os.access's modes.
                           "KEY_512", "OTHER_512", "F_OK", "R_OK", "W_OK", "X_OK"})
CIPHER_NAME = re.compile(r"AES_(?:128|192|256)(?:_[A-Z]+)+")


def _in_public_scope(name: str) -> bool:
    """Whether a tracked path is one the public repository will hold; a
    pattern's * never crosses a directory."""
    return name not in GATE_ITSELF and any(fnmatch.fnmatchcase(name, pattern) for pattern in PUBLIC_SCOPE)


def _public_scope_address(address: ipaddress.IPv4Address) -> bool:
    return address in PRIVATE_EXAMPLES or any(address in block for block in PUBLIC_SCOPE_BLOCKS)


def _public_scope_address_hits(text: str):
    """(position, what) of each IPv4 address or a.b.c.x block, dotted or in a
    name, that the public scope may not quote. A dotted quad no address can
    have is no hit."""
    for pattern, what in ((PUBLIC_IPV4, "IPv4 address"), (PUBLIC_IPV4_BLOCK, "IPv4 block"),
                          (PUBLIC_IPV4_IN_NAME, "IPv4 address in a name")):
        for match in pattern.finditer(text):
            try:
                address = ipaddress.IPv4Address(re.sub(r"[xX]$", "0", match.group(0).replace("_", ".")))
            except ValueError:
                continue
            if not _public_scope_address(address):
                kind = "private" if address.is_private else "public"
                yield match.start(), f"{kind} {what} outside the allowed blocks"


def _shaped_like_a_client_name(name: str) -> bool:
    from netstate.naming import _ROLE_WORDS

    segments = name.partition("-")[2].split("_") if "-" in name else name.split("_")
    return (
        any(NUMBERED_SEGMENT.fullmatch(segment) for segment in segments)
        or any(segment.lower() in _ROLE_WORDS for segment in segments)
        or any(TWO_LETTER_SEGMENT.fullmatch(segment) for segment in segments[1:])
    )


def _in_convention(name: str) -> bool:
    """Whether every part of a name is a part of netstate/naming.py's made-up convention."""
    from netstate.naming import _ROLE_WORDS

    qualifier, _, rest = name.partition("-") if "-" in name else ("", "", name)
    segments = rest.split("_")
    if qualifier and (qualifier not in CONVENTION_QUALIFIERS or segments[0] != CONVENTION_LEADING_ROLE):
        return False
    town = re.compile("(?:" + "|".join(CONVENTION_TOWNS) + r")\d{0,2}")
    role_word = re.compile(r"(?P<word>[A-Z]+)\d{0,2}")

    def known(index: int, segment: str) -> bool:
        word = role_word.fullmatch(segment)
        return bool(
            segment in CONVENTION_SITE_TYPES
            or segment in CONVENTION_SITE_NAMES
            or town.fullmatch(segment)
            or re.fullmatch(r"[A-Z]\d{1,2}|\d{1,2}", segment)
            or (word and word.group("word").lower() in _ROLE_WORDS)
            or (index == 0 and segment == CONVENTION_LEADING_ROLE)
        )

    return all(known(index, segment) for index, segment in enumerate(segments))


def _public_scope_name_hits(text: str):
    """(position, what) of each name of the client convention's shape, in
    capitals or, in a path, in lower case, that the made-up convention does
    not account for."""
    for pattern, what in ((NAME_SHAPE, "hostname of the client convention's shape"),
                          (LOWER_NAME_IN_A_PATH, "hostname of the client convention's shape, in lower case")):
        for match in pattern.finditer(text):
            if pattern is LOWER_NAME_IN_A_PATH and match.group(0).split("_")[0] in COMMAND_WORDS:
                continue
            name = match.group(0).upper()
            if (name in NOT_HOSTNAMES or CIPHER_NAME.fullmatch(name)
                    or not _shaped_like_a_client_name(name) or _in_convention(name)):
                continue
            yield match.start(), what


class ThePublicScopeHoldsNoCustomerMaterial(unittest.TestCase):
    """RELEASE-AUDIT.md section 2: the public repository starts from a tree with no customer-derived name or address.

    A recorded unicon dialog, token-mapped device names and a client's town
    codes reached netstate's comments and tests before; each was replaced by
    hand-written text. These guards make the next one fail the suite.
    """

    def scope(self):
        files = [(name, where, text) for name, where, text in _corpus() if _in_public_scope(name)]
        self.assertTrue(files, "the public scope matched no tracked file")
        return files

    def test_every_ipv4_address_in_the_public_scope_is_one_it_may_quote(self):
        found = [f"{where}:{_line(text, pos)}: {what}" for _, where, text in self.scope()
                 for pos, what in _public_scope_address_hits(text)]
        self.assertEqual(found, [], "addresses the public scope may not quote:\n" + "\n".join(found))

    def test_every_hostname_of_the_client_shape_in_the_public_scope_is_in_the_made_up_convention(self):
        found = [f"{where}:{_line(text, pos)}: {what}" for _, where, text in self.scope()
                 for pos, what in _public_scope_name_hits(text)]
        self.assertEqual(found, [], "names outside the convention in netstate/naming.py:\n" + "\n".join(found))

    def test_the_scope_is_the_whole_repository(self):
        scoped = {name for name, _, _ in self.scope()}
        for name in ("netstate/naming.py", "netstate/commands.yaml", "netstate/cli.py", "tests/test_collector_enable.py",
                     "tests/test_redaction_battery.py", "tests/helpers.py", "README.md", "tests/test_scrub_scan.py"):
            self.assertIn(name, scoped)

    def test_no_test_imports_a_module_this_repository_does_not_ship(self):
        """The tests run on netstate alone: nothing of DiscoNet or its other dependencies."""
        foreign = re.compile(r"^(disconet|rich|anthropic|jinja2|dotenv)\b")
        found = []
        for name, _, text in self.scope():
            if not name.endswith(".py"):
                continue
            for node in ast.walk(ast.parse(text)):
                modules = ([node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0
                           else [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
                found += [f"{name}:{node.lineno}: {module}" for module in modules if foreign.match(module)]
        self.assertEqual(found, [])

    def test_the_convention_allowed_here_is_the_one_naming_documents(self):
        source = (ROOT / "netstate" / "naming.py").read_text(encoding="utf-8")
        block = re.search(r"^# Every example hostname in this module is written in one made-up convention.*?\n\n",
                          source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(block, "netstate/naming.py no longer documents its example convention")
        for word in (CONVENTION_SITE_TYPES + CONVENTION_TOWNS + CONVENTION_SITE_NAMES
                     + tuple(f"{q}-{CONVENTION_LEADING_ROLE}" for q in CONVENTION_QUALIFIERS)):
            self.assertRegex(block.group(0), rf"(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z])")
        for example in re.findall(r"\b(?:[A-Z]-)?[A-Z]{2,3}\d*(?:_[A-Z0-9]+)+\b", block.group(0)):
            self.assertTrue(_in_convention(example), example)

    def test_the_address_guard_refuses_private_space_beyond_the_examples(self):
        def hits(address):
            return [what for _, what in _public_scope_address_hits(address)]

        for allowed in ("192.0.2.1", "198.51.100.33", "203.0.113.7", "10.0.0.1", "10.1.0.11", "10.255.0.3",
                        "127.0.0.1", "169.254.1.1", "224.0.0.5", "0.0.0.0", "0.0.0.255", "255.255.255.0",
                        "128.0.0.4", "dev_10_1_0_11", "999.1.1.1", "Trying 192.0.2.1...", "at 203.0.113.7.",
                        "192.0.2.x", "dev_198_51_100_x", "a five-part version, 15.2.4.7.1"):
            self.assertEqual(hits(allowed), [], allowed)
        # Built from numbers, so this file quotes none of them as text.
        refused = {
            str(ipaddress.IPv4Address((172 << 24) | (16 << 16) | 1)): "private",   # inside 128.0.0.0/2 too
            str(ipaddress.IPv4Address((192 << 24) | (168 << 16) | (1 << 8) | 1)): "private",
            str(ipaddress.IPv4Address((10 << 24) | (77 << 16) | 1)): "private",   # 10/8 past the examples
            str(ipaddress.IPv4Address((130 << 24) | 1)): "public",   # in the audit's /2, not Junos's /16
            PUBLIC_V4: "public",
        }
        for address, kind in refused.items():
            dotted = [f"{kind} IPv4 address outside the allowed blocks"]
            self.assertEqual(hits(address), dotted, address)
            self.assertEqual(hits("\\n" + address), dotted, address)
            # The end of a sentence, and the lines telnet and unicon print.
            self.assertEqual(hits(f"# The jump host is at {address}."), dotted, address)
            self.assertEqual(hits(f"Trying {address}...\nConnected to {address}.\n"), dotted * 2, address)
            self.assertEqual(hits("dev_" + address.replace(".", "_")),
                             [f"{kind} IPv4 address in a name outside the allowed blocks"], address)
            block = address.rsplit(".", 1)[0]
            self.assertEqual(hits(f"# Management addresses are {block}.x."),
                             [f"{kind} IPv4 block outside the allowed blocks"], address)
            self.assertEqual(hits("dev_" + block.replace(".", "_") + "_x"),
                             [f"{kind} IPv4 address in a name outside the allowed blocks"], address)
        # A private example is allowed by itself, not with its /24: the
        # address beside one is refused.
        beside = str(ipaddress.IPv4Address((10 << 24) | 3))
        self.assertEqual(hits(beside), ["private IPv4 address outside the allowed blocks"])
        self.assertEqual(hits("dev_" + beside.replace(".", "_")),
                         ["private IPv4 address in a name outside the allowed blocks"])

    def test_the_name_guard_finds_every_form_of_the_client_shape_and_passes_the_convention(self):
        # Made-up codes of the client's shape, built from parts so that this
        # file carries none for the guards to find: prefix, town and site,
        # tier letter, index; a prefix straight before the tier letter; two
        # bare codes; a place and a role word; a qualified leading role before
        # a named site.
        for parts in (("KJ", "VW3", "T1", "1"), ("KJW", "T1", "1"), ("KJW", "VW"), ("KJW", "EDGE"),
                      ("U-PE", "VW", "MARSH", "1")):
            name = "_".join(parts)
            self.assertEqual([what for _, what in _public_scope_name_hits(f"device {name} here")],
                             ["hostname of the client convention's shape"], name)
        self.assertTrue(list(_public_scope_name_hits(DEVICE)))   # the made-up device above is no exception
        # Source text, where the letter of a string escape is no part of the name.
        self.assertTrue(list(_public_scope_name_hits('"prompt\\n' + DEVICE + '#"')))
        self.assertFalse(list(_public_scope_name_hits('"prompt\\nHUB_QX4_R2_1#"')))
        # The forms a name takes in a dialog and a path: the file unicon names
        # after the device, a three-letter qualifier, more segments, a three-digit
        # site, and the name in lower case as a directory is called after it.
        shaped = "_".join(("KJ", "VW3", "T1", "1"))
        for text in (f"+++ {shaped} logfile /tmp/{shaped}-cli.log +++", "_".join(("ABC-PE", "VW", "MARSH", "1")),
                     "_".join(("KJ", "VW3", "T1", "A", "B", "C", "1")), "_".join(("KJ", "VW123", "T1", "1"))):
            hits = [what for _, what in _public_scope_name_hits(text)]
            self.assertTrue(hits, text)
            self.assertEqual(set(hits), {"hostname of the client convention's shape"}, text)
        for text in (f"snapshots/{shaped.lower()}/state", f"/tmp/{shaped.lower()}-cli.log"):
            self.assertEqual([what for _, what in _public_scope_name_hits(text)],
                             ["hostname of the client convention's shape, in lower case"], text)
        self.assertEqual([what for _, what in _public_scope_name_hits(f"/tmp/{shaped}-cli.log")],
                         ["hostname of the client convention's shape"])
        for text in ("snapshots/hub_qx4_r2_1/state", "/tmp/HUB_QX4_R2_1-cli.log", "R1/state/show_ip_arp.json",
                     "LEAF1/state/show_ipv6_neighbors.json", "cryptographic-algorithm AES_256_CMAC"):
            self.assertEqual(list(_public_scope_name_hits(text)), [], text)
        for name in ("HUB_QX4_R2_1", "HUB_QX4_CORE_C1", "HUB_QX4_L1_NMS", "U-PE_QX_KESTREL_1",
                     "PE_QX_KESTREL_2", "POP_CR", "POP_CR_C2", "HUB_ZV17", "QX_KESTREL"):
            self.assertEqual(list(_public_scope_name_hits(name)), [], name)
        # Code identifiers and constants are no hostnames.
        for text in ("XR_POLICY", "NO_USERNAME_HINT", "DISCONET_USERNAME_2", "AES_256_CMAC", "SITE_SEPARATOR"):
            self.assertEqual(list(_public_scope_name_hits(text)), [], text)
        self.assertEqual(list(_public_scope_name_hits("_".join(("CORE", "LINK", "TO", "R2")))), [])


# DiscoNet's widening fixtures (a folder of its test fixtures) are sanitised
# configurations from production networks, and they stay in the private
# repository. No file of theirs, no path to them and none of their device
# names may appear here. Their names are a network letter, a role and a
# number; the roles are listed, never a whole name, so this file holds none.
WIDENING_ROLES = ("igw", "p", "pe", "agg", "ipsec-pe", "iptv-acc", "iptv-core", "rr", "ext-pe")
WIDENING_NAME = re.compile(r"(?<![\w-])[a-z]-(?:" + "|".join(sorted(map(re.escape, WIDENING_ROLES), key=len, reverse=True))
                           + r")-\d+(?![\w-])", re.IGNORECASE)
# Their folder and the file kinds it holds, built from parts for the same reason.
WIDENING_PATH = re.compile("|".join(("fixtures" + r"[/\\]" + "widening", "expected" + "_gaps", "baseline" + "_statements",
                                     r"(?<![\w-])net-[a-z]/")), re.IGNORECASE)


def _widening_hits(text: str):
    for pattern, what in ((WIDENING_NAME, "a widening fixture's device name"),
                          (WIDENING_PATH, "a path or file of the widening fixtures")):
        for match in pattern.finditer(text):
            yield match.start(), what


class TheWideningFixturesStayPrivate(unittest.TestCase):
    """No widening fixture, path to one, or device name of theirs is in this repository."""

    def test_no_tracked_path_is_a_widening_fixture(self):
        listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        self.assertEqual([name for name in listed.split("\0") if name and list(_widening_hits(name))], [])

    def test_no_tracked_file_names_one(self):
        found = [f"{where}:{_line(text, pos)}: {what}" for _, where, text in _corpus()
                 for pos, what in _widening_hits(text)]
        self.assertEqual(found, [], "widening fixture material:\n" + "\n".join(found))

    def test_the_guard_finds_their_names_and_paths_and_passes_the_convention(self):
        role = WIDENING_ROLES   # names built from parts, so this file carries none
        for name in ("-".join(("a", role[2], "1")), "-".join(("B", role[5], "12")), "-".join(("c", role[8], "3")),
                     "/".join(("tests", "fixtures", "widening", "README.md")), "-".join(("b", role[1], "1")) + "." + "_".join(("expected", "gaps")) + ".json"):
            self.assertTrue(list(_widening_hits(f"see {name} here")), name)
        for text in ("rbt-ald-pe1", "PE_QX_KESTREL_1", "a-pe", "ge-0/0/1", "xe-1-2", "R1", "pe1", "ab-pe-1"):
            self.assertEqual(list(_widening_hits(text)), [], text)


class TheDocumentsNameEveryPlatform(unittest.TestCase):
    """A registry entry that the README does not list is one the reader cannot use."""

    def test_the_readme_lists_every_platform_key_as_an_os_value(self):
        from netstate import platforms

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        missing = [p.key for p in platforms.PLATFORMS if f"`{p.key}`" not in readme]
        self.assertEqual(missing, [], f"README.md never names os: {missing}")

    def test_the_commands_file_header_names_every_feature_key(self):
        from netstate.collector import ALL_FEATURES, DEFAULT_COMMANDS_FILE

        header = "\n".join(
            line for line in DEFAULT_COMMANDS_FILE.read_text(encoding="utf-8").splitlines()[:60]
            if line.startswith("#")
        )
        missing = sorted(key for key in ALL_FEATURES if not re.search(rf"\b{key}\b", header))
        self.assertEqual(missing, [], f"commands.yaml header never names {missing}")


class TheDocumentsQuoteNoTestCount(unittest.TestCase):
    """BUG-354: TESTING.md said 1973 tests and ARCHITECTURE.md 1669 while the suite ran 2170.

    Every fix adds tests, so a count written into a document is wrong by the
    next commit, and it was: three documents went stale this way before.
    What the documents promise is that the suite ends OK.
    """

    DOCUMENTS = ("README.md", "CONTRIBUTING.md")
    COUNT = re.compile(r"\b\d[\d,]*\s+(?:tests|green|pass)\b")

    def test_no_document_that_describes_the_suite_quotes_how_many_tests_it_has(self):
        quoted = [
            f"{name}:{number}: {match.group(0)}"
            for name in self.DOCUMENTS
            for number, line in enumerate((ROOT / name).read_text(encoding="utf-8").splitlines(), 1)
            for match in self.COUNT.finditer(line)
        ]
        self.assertEqual(quoted, [])


class EveryTestFileRunsWholeOnItsOwn(unittest.TestCase):
    """BUG-196, BUG-189: classes defined below the `__main__` guard were skipped.

    `python tests/test_store.py` ran unittest.main() when the guard
    was reached, before the classes below it existed, and 22 files had some.
    Discovery runs them all, so only a file run on its own lost them.
    """

    def test_the_main_guard_is_the_last_statement_of_every_test_file(self):
        import ast

        misplaced = []
        for path in sorted((ROOT / "tests").glob("test_*.py")):
            body = ast.parse(path.read_text(encoding="utf-8")).body
            guards = [index for index, node in enumerate(body)
                      if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)]
            if guards not in ([], [len(body) - 1]):
                misplaced.append(path.name)
        self.assertEqual(misplaced, [])


class NothingImportedIsCollectedAsATest(unittest.TestCase):
    """BUG-353: pytest collects every module-level function named test*, imported ones too.

    `testbed_secrets`, imported by name from the collector, was collected as a
    test that asked for a fixture called testbed, one error in every pytest run.
    """

    def test_no_test_module_holds_an_imported_function_named_like_a_test(self):
        import importlib
        import inspect
        import pkgutil

        import tests

        stray = []
        for info in pkgutil.iter_modules(tests.__path__):
            if not info.name.startswith("test_"):
                continue
            module = importlib.import_module(f"{tests.__name__}.{info.name}")
            stray += [
                f"{info.name}: {name}"
                for name, value in vars(module).items()
                if name.startswith("test") and inspect.isfunction(value)
                and value.__module__ != module.__name__
            ]
        self.assertEqual(stray, [], "import these by module or under another name")


if __name__ == "__main__":
    unittest.main()
