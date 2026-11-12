"""One file a prospect sends and the owner can trust: `export` and `verify`.

A prospect runs the Collector on their own network and sends the result. What
arrives has to be three things at once: the collection and nothing else (no
generated document, no estate database, no `.env`, no login transcript), with
no credential in it, and checkably the collection that was made. `export`
packs a snapshot into one gzip-compressed tar file to that rule and `verify`
checks one, in place, without unpacking it.

What goes in is decided by the collection manifest, never by walking the
directory. A snapshot directory accumulates whatever was generated from it
(the HTML page, the Word document, the workbooks, the diagrams, the Community
report's folder) and sits beside the estate database; a walk would carry any
of it that a filter forgot. The manifest names exactly the files the run
wrote, and the archive holds those, the manifest itself, the testbed with every
secret replaced and the export's own manifest. Every member is also held to a
positive shape rule and checked against a list of kinds that never belong, so
that a manifest edited to name `discovered-network.html` or `../disconet.db`
is refused rather than obeyed.

The archive is deterministic. Members are sorted, carry no owner, one mode and
one time (the collection's start), and the gzip header carries no time or
name, so the same snapshot exported with the same `exported_at` is the same
bytes. Through the CLI `exported_at` is now, so two exports of one snapshot
differ in the export manifest only, and so in the archive's checksum: a
checksum told over the phone names one export, not one snapshot, and an
archive exported again needs its new checksum told again.

The export manifest restates the collection's summary (which devices, which
OS, which features, when) and lists the SHA-256 of every member. `verify`
re-derives that summary from the manifest.json inside the archive rather than
trusting it, so an edited summary fails as surely as an edited file. A
signature over the export manifest is opt-in (`netstate.signing`).

netstate stands alone: nothing here imports DiscoNet, and the console output
is the CLI's.
"""

from __future__ import annotations

import collections
import contextlib
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tempfile
import unicodedata
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, BinaryIO, Callable

import yaml

from netstate import __version__, signing, store
from netstate.collector import (
    CREDENTIAL_KEYS, DEFAULT_COMMANDS_FILE, LOGIN_PROMPTS_KEY, REDACTION_MARKER, CollectionError, redact,
)

EXPORT_FORMAT = "disconet-snapshot-export"
EXPORT_FORMAT_VERSION = 1
ARCHIVE_SUFFIX = ".export.tar.gz"

MANIFEST_NAME = "manifest.json"
TESTBED_NAME = "testbed.yaml"
EXPORT_MANIFEST_NAME = "export-manifest.json"
SIGNATURE_NAME = "export-manifest.sig"
# The keys of the signature file, as signing.signature_document writes it.
# Nothing hashes that file (it cannot list itself), so a key beyond these
# would be a place to carry anything in an archive that verify called OK.
SIGNATURE_KEYS = frozenset({"alg", "public_key", "signature"})
# The only files an archive holds directly under its top folder.
TOP_LEVEL_NAMES = (MANIFEST_NAME, TESTBED_NAME, EXPORT_MANIFEST_NAME, SIGNATURE_NAME)
# The manifest keys that name a file a run wrote, and the one shape each
# folder's files have: raw text in raw/, parsed state in state/.
FILE_KEYS = ("raw_file", "state_file")
FOLDER_SUFFIXES = {"raw": ".txt", "state": ".json"}

# Kinds that never belong in an export, whatever names them. Named in the
# message as what they are, so a refusal says "a generated output" or "the
# estate database" and not only that a rule was broken.
GENERATED_SUFFIXES = (
    ".html", ".htm", ".md", ".docx", ".doc", ".xlsx", ".xlsm", ".xls", ".drawio", ".svg",
    ".png", ".jpg", ".jpeg", ".pdf",
)
DATABASE_SUFFIXES = (".db-wal", ".db-shm", ".db", ".sqlite")
OTHER_SUFFIXES = {
    ".log": "a log, which can hold a login dialog",
    ".tmp": "a temporary file",
    ".env": "a credentials file (.env)",
}
FORBIDDEN_NAMES = {
    "lifecycle.yaml": "the estate's lifecycle data (lifecycle.yaml)",
    "docmeta.yaml": "the estate's document metadata (docmeta.yaml)",
    ".env": "a credentials file (.env)",
    "known_hosts": "the estate's pinned host keys (known_hosts)",
}
FORBIDDEN_PARTS = {
    "community": "a generated output (the Community report's community/ folder)",
    "sections": "a generated output (a document's sections/ folder)",
}

# A key whose value is a secret. A hand-written testbed keeps its secrets under
# whatever name its author chose (`pwd`, `tacacs_key`, `authKey`, pyATS's older
# `passwords:` mapping), and a list of whole names missed most of them. So a
# key is read as words: split at anything that is not a letter or a digit and
# at each camelCase hump, lower-cased, a plural's ending dropped. It names a
# secret when one of its words is in SECRET_WORDS, when the key run together
# ends in one of SECRET_ENDINGS (`privkey`, `adminpw`), or when it holds one of
# SECRET_KEY_WORDS anywhere (`snmpcommunitystring`), as well as when it is one
# of the collector's own CREDENTIAL_KEYS. `key` and `pin` are words of their
# own, so `key_filename` and `host_key_checking` go too: over-redacting a
# harmless key is the way to be wrong that leaks nothing.
SECRET_WORDS = frozenset({
    "password", "passwd", "pass", "pwd", "pw", "passphrase", "passcode", "secret", "token", "community",
    "psk", "key", "apikey", "bearer", "otp", "pin",
})
SECRET_ENDINGS = ("key", "pw", "pwd", "pass", "password", "secret", "token")
SECRET_KEY_WORDS = ("password", "passwd", "passphrase", "passcode", "secret", "token", "community")
# The structural keys a secret sits under and the name a login is given
# with. None of them is a secret, so what they hold is walked rather than
# replaced, and the usernames stay for the owner to read.
NOT_SECRET_KEYS = frozenset({"credentials", "credential", "username", "user", "login"})
# The words of a key: runs of capitals not followed by a lower-case letter
# (`API` in `APIKey`), a word with its capital (`Key`), and digits apart.
KEY_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
KEY_SEPARATOR = re.compile(r"[^A-Za-z0-9]+")
# A value that is exactly one of these names a variable, not a value: pyATS
# reads %ENV{NAME} from the environment and %ASK{...} from the keyboard, so
# the reference is kept and tells the owner how the run was given its login.
REFERENCE = re.compile(r"%ENV\{[^{}\s]+\}|%ASK\{[^{}]*\}")
# %ENC{...} is the secret itself, encoded reversibly with a key anyone with
# pyATS has. A string holding one is replaced whole, under whatever key.
ENCODED = "%ENC{"
# pyATS testbed markup: `%{testbed.custom.lab_pw}` is the value at that dotted
# path from the top of the same file, put in its place when pyATS loads it. A
# secret's key holding one says where the secret is, so the value it names is
# replaced as well as the reference.
MARKUP = re.compile(r"%\{([\w.-]+)\}")
# A password typed on a command line inside a string: a jump host's
# `command: sshpass -p X ssh ...`, an `ssh_options` whose ProxyCommand runs
# sshpass, a tool's `--password X`. The argument goes, quoted or not; the
# marker already in its place is left alone, so that verify, redacting what
# export wrote, finds nothing more. `-p` is sshpass's only after `sshpass`
# (ssh's own `-p` is a port), and the first `-p` after it is taken, which can
# be ssh's port when sshpass read the password from elsewhere: a port lost is
# the way to be wrong that leaks nothing.
_ARGUMENT = rf"(?:{re.escape(REDACTION_MARKER)}|'[^'\n]*'|\"[^\"\n]*\"|[^\s'\"]+)"
COMMAND_SECRET = re.compile(
    rf"(?P<head>\bsshpass\b[^\n]*?\s-p\s*|--pass(?:word|wd)?(?:=|\s+))(?P<value>{_ARGUMENT})"
)
# Where one ssh option starts inside an `ssh_options` string. The collector's
# device-output rules read a line as a device's configuration line, and
# DiscoNet's own `-o KexAlgorithms=+...-sha1 -o HostKeyAlgorithms=+ssh-rsa`
# reads there as an SNMPv3 `sha1 <key>`: everything after the first `sha1`
# went. Each option is read on its own, where no such pair forms.
SSH_OPTION_START = re.compile(r"(\s+)(?=-o\s*[A-Za-z])")
# A literal found under a secret's key is also looked for in every other
# string of the testbed (a jump host's command line that repeats it). Four
# characters, as the collector's transcript sweep: shorter matches half a file.
SWEEP_MINIMUM = 4
# How many values a testbed may hold once its YAML aliases are followed. An
# alias of an alias of a list nine deep is a few hundred bytes and hundreds of
# millions of values to walk, and verify reads the testbed of an archive
# someone else made: the walk stops here rather than hang. A real testbed of
# thousands of devices is a few hundred thousand.
TESTBED_VALUE_LIMIT = 1_000_000

SHA256_HEX = re.compile(r"[0-9a-f]{64}")
SNAPSHOT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
CHUNK = 1 << 20
# How much of a member verify keeps in memory to read: the manifests and the
# testbed. Everything else is only hashed, a chunk at a time.
KEEP_LIMIT = 256 << 20

TESTBED_HEADER = (
    "# Testbed exported by DiscoNet (netstate {version}) with snapshot {snapshot_id}.\n"
    "#\n"
    "# Every credential in it is replaced with \"{marker}\": passwords,\n"
    "# secrets, tokens, keys, PINs, SNMP communities, %ENC{{...}} values, the\n"
    "# answers to login prompts, the values %{{...}} references point at, and\n"
    "# passwords inside command lines and URLs. A value that is a %ENV{{...}} or\n"
    "# %ASK{{...}} reference is kept, since it names a variable rather than holding\n"
    "# a value, and usernames are kept. The original file's comments are dropped:\n"
    "# a hand-written testbed can hold a password in a comment.\n"
    "\n"
)

NEXT_STEP = (
    "encrypt the archive before it leaves this machine, with age and the recipient's age "
    "public key (docs/RUN-GUIDE.md)"
)
SECOND_CHANNEL = (
    "send this line to the person receiving the export by a second channel (a phone call, a "
    "text message or a separate email), never in the same message as the archive: it is what "
    "proves the archive came from you"
)


class ExportRefused(CollectionError):
    """A snapshot that cannot be exported as it stands; nothing was written."""


class OversizedTestbed(ExportRefused):
    """A testbed that holds more than TESTBED_VALUE_LIMIT values once its aliases are followed."""


# --------------------------------------------------------------------------
# What may be in an archive
# --------------------------------------------------------------------------


def forbidden_kind(relative: str) -> str | None:
    """What ``relative`` is, when it is a kind of file no export carries; None otherwise.

    By any folder on the way (community/, sections/), by name, then by
    suffix. Case is ignored: `REPORT.HTML` is as much a generated page as
    `report.html`, and on a laptop's file system it may be the same file.
    """
    parts = [part.lower() for part in PurePosixPath(relative).parts]
    if not parts:
        return None
    for part in parts:
        if part in FORBIDDEN_PARTS:
            return FORBIDDEN_PARTS[part]
    name = parts[-1]
    if name in FORBIDDEN_NAMES:
        return FORBIDDEN_NAMES[name]
    for suffix in GENERATED_SUFFIXES:
        if name.endswith(suffix):
            return f"a generated output ({suffix})"
    for suffix in DATABASE_SUFFIXES:
        if name.endswith(suffix):
            return f"the estate database ({suffix})"
    for suffix, what in OTHER_SUFFIXES.items():
        if name.endswith(suffix):
            return what
    return None


def _plain_part(part: str) -> bool:
    return bool(part) and part not in (".", "..") and not part.startswith(".") and "\\" not in part


def collected_file_shape(relative: str) -> bool:
    """Is ``relative`` of the one shape a run writes a file in?

    That is `<device>/raw/<name>.txt` or `<device>/state/<name>.json`, and
    nothing deeper, shallower or hidden.
    """
    parts = relative.split("/")
    if len(parts) != 3:
        return False
    device, folder, name = parts
    suffix = FOLDER_SUFFIXES.get(folder)
    return (
        suffix is not None and _plain_part(device) and _plain_part(name)
        and name.endswith(suffix) and len(name) > len(suffix)
    )


def member_shape(relative: str) -> bool:
    """The positive rule for a path under an archive's top folder: one of the four top files, or a collected file."""
    return relative in TOP_LEVEL_NAMES or collected_file_shape(relative)


def _control_character(text: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in text)


def _path_problem(relative: Any) -> str | None:
    """Why ``relative`` cannot name a file inside a snapshot, by its text alone; None when it can."""
    if not isinstance(relative, str) or not relative:
        return "is not a file name"
    if relative.startswith(("/", "\\")) or PureWindowsPath(relative).drive:
        return "is an absolute path"
    if ".." in relative:
        return "climbs out of the snapshot (..)"
    if "\\" in relative:
        return "has a backslash, which no collection writes"
    # A pax header can give a member a name with a NUL or an escape in it.
    # Python keeps the whole name, a C tar may stop at the NUL and write
    # over another member's file, and an escape in a name printed on the
    # owner's terminal is a command to that terminal. No collection names a
    # file so: collector.slugify keeps lower-case letters, digits and
    # underscores, and a device's folder is its name in the testbed.
    if _control_character(relative):
        return "has a control character, which no collection writes"
    return None


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise ValueError(f"the key {key!r} appears twice in one object")
        found[key] = value
    return found


def load_json(data: bytes) -> Any:
    """JSON as export writes it: UTF-8, and no key twice in one object; ValueError otherwise.

    json.loads keeps the last of two equal keys and other readers keep the
    first, so a manifest holding `"synthetic": false` and then `"synthetic":
    true` says one thing to verify and another to whoever reads it with
    another tool. Neither the collector nor export writes a key twice, so
    one that holds a key twice was made by hand and is refused, by export
    for the manifest.json it packs and by verify for every JSON member.
    """
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys)


def _safe_snapshot_id(value: Any) -> bool:
    return isinstance(value, str) and bool(SNAPSHOT_ID.fullmatch(value)) and ".." not in value


# --------------------------------------------------------------------------
# The summary an export manifest restates
# --------------------------------------------------------------------------


def _instant(value: Any) -> datetime | None:
    """An ISO-8601 time from a manifest, in UTC; None for one that is absent or unreadable.

    A time with no offset is read as UTC. The collector has always stamped
    its times in UTC; an offset-free one is from a manifest written by hand.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _utc_text(moment: datetime | None) -> str | None:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if moment is not None else None


def _list_of_text(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, (list, tuple)) else []


def _text_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _versions(value: Any) -> list[str]:
    """A merged run's collector versions: the distinct non-empty texts, sorted, as merge.py writes them."""
    items = value if isinstance(value, (list, tuple)) else ()
    return sorted({item for item in items if isinstance(item, str) and item.strip()})


def collector_version_of(manifest: dict[str, Any]) -> str | None:
    """The engine that collected a single run, as store.py reads it.

    A run collected before the engine had its own package (before the
    netstate rename) says which DiscoNet did, under `disconet_version`, and
    older ones under `version`. A merge's `disconet_version` is the merging
    DiscoNet's, never a collector's, so this is for a run that is no merge.
    """
    for key in ("netstate_version", "disconet_version", "version"):
        text = _text_or_none(manifest.get(key))
        if text:
            return text
    return None


def collection_start(manifest: dict[str, Any]) -> datetime | None:
    """When the collection began: a merge's earliest source (`collected_from`), else the run's `created_at`.

    A merge's `created_at` is its newest source's, often a retry round of a
    few devices minutes long, while most of its data was read before.
    """
    return _instant(manifest.get("collected_from")) or _instant(manifest.get("created_at"))


def merge_sources(manifest: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Each run a merge was made of, as `disconet merge` recorded it in merged_from; None for a run that is no merge.

    Every field is brought to its type here, whatever the manifest holds, so
    that what export writes and verify shows can be relied on to be text, a
    list of text or None. A merge whose merged_from is no list has sources
    nobody can read: an empty list, not a single run's summary.
    """
    merged = manifest.get("merged_from")
    if not merged:
        return None
    sources = []
    for entry in merged if isinstance(merged, list) else ():
        entry = entry if isinstance(entry, dict) else {}
        recorded = entry.get("commands_sha256")
        sources.append({
            "snapshot_id": str(entry.get("snapshot_id") or ""),
            "started_utc": _utc_text(_instant(entry.get("created_at"))),
            "finished_utc": _utc_text(_instant(entry.get("finished_at"))),
            "collector_versions": _versions(entry.get("collector_versions")),
            "commands_sha256": recorded if isinstance(recorded, str) else None,
        })
    return sources


def collection_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    """The collection as the export manifest states it, derived from the collection manifest alone.

    `export` writes exactly this into the export manifest, and `verify`
    derives it again from the manifest.json inside the archive and compares,
    so the statement is only ever as true as the collection it describes.
    Every value is of one type whatever the manifest holds (text or None, a
    list of text, a dict of dicts), because the manifest is a prospect's
    file and the summary is printed by code that must not fail on it.

    A merge is described by its sources: the window runs from the earliest
    (`collected_from`) to the finish the merge recorded, and the collector
    version is the one every source shares, or None when they differ or one
    recorded none, with `collector_versions` listing them all.
    """
    devices = manifest.get("devices") if isinstance(manifest.get("devices"), dict) else {}
    described = {
        str(name): {
            "os": _text_or_none(entry.get("os")) if isinstance(entry, dict) else None,
            "platform": _text_or_none(entry.get("platform")) if isinstance(entry, dict) else None,
            "connected": bool(entry.get("connected")) if isinstance(entry, dict) else False,
        }
        for name, entry in devices.items()
    }
    finished = _instant(manifest.get("finished_at"))
    sources = merge_sources(manifest)
    if sources is None:
        version = collector_version_of(manifest)
        versions = [version] if version else []
    else:
        versions = sorted({text for source in sources for text in source["collector_versions"]})
        complete = bool(sources) and all(source["collector_versions"] for source in sources)
        version = versions[0] if complete and len(versions) == 1 else None
    merged = manifest.get("merged_from")
    interrupted = manifest.get("interrupted")
    # Absent is not none: a run made before feature selection existed read
    # everything (collector.Snapshot.features), and saying "collected: none"
    # of it would say the opposite.
    features = manifest.get("features")
    return {
        "snapshot_id": str(manifest.get("snapshot_id") or ""),
        "estate": _text_or_none(manifest.get("estate")),
        "synthetic": manifest.get("synthetic") is True,
        "synthetic_notice": _text_or_none(manifest.get("synthetic_notice")),
        "collector_version": version,
        "collector_versions": versions,
        "collection": {
            "started_utc": _utc_text(collection_start(manifest)),
            "finished_utc": _utc_text(finished),
            "finished_recorded": finished is not None,
        },
        "sources": sources,
        "device_count": len(described),
        "devices_connected": sum(1 for entry in described.values() if entry["connected"]),
        "devices": described,
        "features": _list_of_text(features) if features is not None else None,
        "features_recorded": features is not None,
        "features_skipped": _list_of_text(manifest.get("features_skipped")),
        "run": {
            "interrupted": interrupted if isinstance(interrupted, dict) and interrupted else None,
            "retry_of": str(manifest.get("retry_of") or ""),
            "merged_from": (list(merged) if isinstance(merged, list) else []) if merged else None,
            "devices_not_requested": _list_of_text(manifest.get("devices_not_requested")),
        },
    }


def named_files(manifest: dict[str, Any]) -> list[tuple[str, str, Any]]:
    """Every (device, command, path) the manifest names as a file the run wrote, in manifest order."""
    found: list[tuple[str, str, Any]] = []
    devices = manifest.get("devices") if isinstance(manifest.get("devices"), dict) else {}
    for name, entry in devices.items():
        commands = entry.get("commands") if isinstance(entry, dict) else None
        for command in commands if isinstance(commands, list) else ():
            if not isinstance(command, dict):
                continue
            for key in FILE_KEYS:
                # Falsy is no file, as store.files_pruned reads it: a command
                # that failed wrote nothing and names nothing.
                if command.get(key):
                    found.append((str(name), str(command.get("command", "")), command.get(key)))
    return found


# --------------------------------------------------------------------------
# The testbed, without its secrets
# --------------------------------------------------------------------------


def _singular(word: str) -> set[str]:
    """A word and what it is with a plural's ending taken off: `passwords`, `keys`, `communities`."""
    forms = {word}
    if word.endswith("ies"):
        forms.add(word[:-3] + "y")
    if word.endswith("es"):
        forms.add(word[:-2])
    if word.endswith("s"):
        forms.add(word[:-1])
    return forms


def _key_words(key: Any) -> list[str]:
    return [word.lower() for part in KEY_SEPARATOR.split(str(key)) for word in KEY_WORD.findall(part)]


def _secret_key(key: Any) -> bool:
    """Does a testbed key name a secret? See SECRET_WORDS for the rule."""
    lowered = str(key).lower()
    if lowered in NOT_SECRET_KEYS:
        return False
    if lowered in CREDENTIAL_KEYS or any(word in lowered for word in SECRET_KEY_WORDS):
        return True
    if any(form in SECRET_WORDS for word in _key_words(key) for form in _singular(word)):
        return True
    joined = KEY_SEPARATOR.sub("", lowered)
    return any(form.endswith(SECRET_ENDINGS) for form in _singular(joined))


def _is_reference(value: Any) -> bool:
    return isinstance(value, str) and bool(REFERENCE.fullmatch(value))


@dataclass
class _Redacting:
    """One testbed's redaction under way.

    ``literals`` are the values replaced under a secret's key, looked for
    again everywhere else; ``targets`` the places a %{...} reference under a
    secret's key points at, as (id of the mapping or list, key or index), so
    that an alias of the same mapping is the same place.
    """

    root: Any
    literals: list[str] = field(default_factory=list)
    targets: set[tuple[int, Any]] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    values: int = 0

    def count(self) -> None:
        self.values += 1
        if self.values > TESTBED_VALUE_LIMIT:
            raise OversizedTestbed(
                f"holds more than {TESTBED_VALUE_LIMIT:,} values once its YAML aliases are followed: "
                f"no testbed a collection reads is that large"
            )

    def remember(self, value: Any) -> None:
        """A value just replaced, to be looked for elsewhere; a block scalar's also without its newline."""
        if isinstance(value, str):
            self.literals.extend({value, value.strip()})
        elif not isinstance(value, bool):
            # A numeric PIN, read by YAML as a number, or a date: found again
            # by its text, as a number or inside a string.
            self.literals.append(str(value))


def _where(where: str, key: Any) -> str:
    return f"{where}.{key}" if where else str(key)


def _find_markup(state: _Redacting, node: Any, secret: bool = False, where: str = "", prompts: bool = False) -> None:
    """First pass: every %{...} reference held under a secret's key, resolved to the place it names.

    This pass also counts the values against TESTBED_VALUE_LIMIT. It walks
    every value the later passes walk, so it is the one that has to stop an
    alias bomb before they start.
    """
    state.count()
    if isinstance(node, dict):
        for key, value in node.items():
            inner = secret or _secret_key(key) or (prompts and str(key).lower() == "response")
            listed = str(key).lower() == LOGIN_PROMPTS_KEY and isinstance(value, list)
            _find_markup(state, value, inner, _where(where, key), prompts=listed)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _find_markup(state, item, secret, f"{where}[{index}]", prompts=prompts)
    elif secret and isinstance(node, str):
        match = MARKUP.fullmatch(node)
        if match:
            _resolve_markup(state, match.group(1), where)


def _markup_slot(node: Any, parts: list[str]) -> tuple[Any, Any] | None:
    """The (mapping or list, key or index) a dotted markup path names from ``node``; None when it names nothing.

    A device's name may hold dots (`devices.pe1.example.net.credentials`),
    so at each mapping the longest run of parts that is one of its keys is
    tried first.
    """
    if not parts:
        return None
    if isinstance(node, dict):
        names = {str(key): key for key in node}
        for size in range(len(parts), 0, -1):
            key = names.get(".".join(parts[:size]))
            if key is None and ".".join(parts[:size]) not in names:
                continue
            rest = parts[size:]
            if not rest:
                return node, key
            found = _markup_slot(node[key], rest)
            if found is not None:
                return found
        return None
    if isinstance(node, list) and parts[0].isdigit() and int(parts[0]) < len(node):
        index = int(parts[0])
        return (node, index) if len(parts) == 1 else _markup_slot(node[index], parts[1:])
    return None


def _resolve_markup(state: _Redacting, path: str, where: str) -> None:
    """Mark the place `%{path}` names, and the place that names if it is a reference too."""
    seen: set[tuple[int, Any]] = set()
    while True:
        slot = _markup_slot(state.root, path.split("."))
        if slot is None:
            state.warnings.append(
                f"the testbed's {where} is the reference %{{{path}}}, which names no value in the testbed "
                f"itself (pyATS resolves `self.` and some other markup only when it loads the file): the "
                f"reference is replaced, but the value it stands for is not found, so check the archive's "
                f"testbed.yaml for it before sending the archive"
            )
            return
        container, key = slot
        if (id(container), key) in seen:
            return
        seen.add((id(container), key))
        state.targets.add((id(container), key))
        value = container[key]
        match = MARKUP.fullmatch(value) if isinstance(value, str) else None
        if match is None:
            return
        path, where = match.group(1), path


def _replace_secret(state: _Redacting, value: Any) -> tuple[Any, int]:
    """A value held under a secret's key, replaced unless it holds nothing or names a variable.

    A mapping or a list keeps its shape and has every value in it replaced,
    however deep: whatever it holds, it is held under that name, and the
    %ENV references in it still say how the run was given its login.
    """
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        count = 0
        for key, item in value.items():
            out[key], replaced = _replace_secret(state, item)
            count += replaced
        return out, count
    if isinstance(value, list):
        items = []
        count = 0
        for item in value:
            redacted, replaced = _replace_secret(state, item)
            items.append(redacted)
            count += replaced
        return items, count
    # Nothing to hide in an empty value, and the marker in its place would
    # say a password had been there.
    if value is None or value == "":
        return value, 0
    # Already replaced: what verify finds in a testbed export wrote.
    if _is_reference(value) or value == REDACTION_MARKER:
        return value, 0
    state.remember(value)
    return REDACTION_MARKER, 1


def _hide_argument(state: _Redacting, match: re.Match, hidden: list[str]) -> str:
    """A command line's password replaced, its quotes kept; one already replaced, or empty, left as it is."""
    value = match.group("value")
    quote = value[0] if len(value) > 1 and value[0] in "'\"" and value[-1] == value[0] else ""
    inner = value[1:-1] if quote else value
    if not inner or inner == REDACTION_MARKER:
        return match.group(0)
    state.remember(inner)
    hidden.append(inner)
    return f"{match.group('head')}{quote}{REDACTION_MARKER}{quote}"


def _redact_string(state: _Redacting, text: str) -> tuple[str, int]:
    """A string under no secret's key: an %ENC value, a command line's password, and what device output would hide.

    The device-output rules (collector.redact) are what catch `password X`
    in a note and the `user:password@` of a URL. A string they change gains
    a marker; one they leave as it was, or only re-space, is kept exactly,
    so that a testbed's own text is not reflowed.
    """
    if _is_reference(text) or text == REDACTION_MARKER:
        return text, 0
    if ENCODED in text:
        state.remember(text)
        return REDACTION_MARKER, 1
    hidden: list[str] = []
    text = COMMAND_SECRET.sub(lambda match: _hide_argument(state, match, hidden), text)
    count = len(hidden)
    pieces = SSH_OPTION_START.split(text)
    for index in range(0, len(pieces), 2):
        piece = pieces[index]
        redacted, _lines = redact(piece, automated=True)
        if redacted.count(REDACTION_MARKER) > piece.count(REDACTION_MARKER):
            pieces[index] = redacted + ("\n" if piece.endswith("\n") and not redacted.endswith("\n") else "")
            count += 1
    return "".join(pieces), count


def _redact_node(state: _Redacting, node: Any, prompts: bool = False) -> tuple[Any, int]:
    """Second pass: the tree with every secret replaced.

    ``prompts`` is true for the entries of a `custom.login_prompts` list:
    what a login is told can be a password or a one-time code, which is why
    the collector logs an answer by its length alone, so every `response` is
    replaced and the pattern it answers kept for the owner to read. The
    pattern is what the device prints, never what is typed, and is kept as
    written: read by the device-output rules, `token code:\\s*` lost its
    `code:\\s*` as if it were a token. Only the sweep looks at it.
    """
    if isinstance(node, dict):
        out: dict[Any, Any] = {}
        count = 0
        for key, value in node.items():
            if (
                _secret_key(key) or (prompts and str(key).lower() == "response")
                or (id(node), key) in state.targets
            ):
                out[key], replaced = _replace_secret(state, value)
            elif prompts and str(key).lower() == "pattern" and isinstance(value, str):
                out[key], replaced = value, 0
            else:
                listed = str(key).lower() == LOGIN_PROMPTS_KEY and isinstance(value, list)
                out[key], replaced = _redact_node(state, value, prompts=listed)
            count += replaced
        return out, count
    if isinstance(node, list):
        items = []
        count = 0
        for index, item in enumerate(node):
            if (id(node), index) in state.targets:
                redacted, replaced = _replace_secret(state, item)
            else:
                redacted, replaced = _redact_node(state, item, prompts=prompts)
            items.append(redacted)
            count += replaced
        return items, count
    if isinstance(node, str):
        return _redact_string(state, node)
    return node, 0


def _sweep(node: Any, literals: list[str], texts: frozenset[str]) -> tuple[Any, int]:
    """Third pass: every other value that repeats a literal already replaced, with the literal replaced in it too.

    A number is matched by its text: a PIN under `password:` that YAML read
    as a number is found again as a number elsewhere, aliased (`*pin`) or
    written out, and as digits inside a string.
    """
    if isinstance(node, dict):
        out: dict[Any, Any] = {}
        count = 0
        for key, value in node.items():
            out[key], replaced = _sweep(value, literals, texts)
            count += replaced
        return out, count
    if isinstance(node, list):
        items = []
        count = 0
        for item in node:
            swept, replaced = _sweep(item, literals, texts)
            items.append(swept)
            count += replaced
        return items, count
    if isinstance(node, str):
        if node == REDACTION_MARKER or _is_reference(node):
            return node, 0
        text = node
        for literal in literals:
            if literal in text:
                text = text.replace(literal, REDACTION_MARKER)
        return text, int(text != node)
    if node is not None and not isinstance(node, bool) and str(node) in texts:
        return REDACTION_MARKER, 1
    return node, 0


def redact_testbed(data: Any, warnings: list[str] | None = None) -> tuple[Any, int]:
    """The testbed tree with every credential replaced by the marker, and how many values were.

    Replaced: every value held under a key that names a secret (see
    SECRET_WORDS), each value in a mapping or list held under one, every
    answer of a `custom.login_prompts` entry, the value a %{...} reference
    under a secret's key points at, any string holding %ENC{...}, the
    password of a `sshpass -p` or `--password` inside a string, and what the
    collector's device-output rules hide in any other string (`password X`,
    a URL's `user:password@`). Kept: a value that is exactly a %ENV{...} or
    %ASK{...} reference, an empty one, and everything else, usernames among
    it. Then every other value that repeats one of the literals just
    replaced has it replaced there too, and is counted.

    ``warnings`` gets what the owner should know and the tree cannot say: a
    %{...} reference that names nothing in the file. OversizedTestbed for a
    tree too large to walk, RecursionError for one that holds itself.
    """
    state = _Redacting(root=data)
    _find_markup(state, data)
    redacted, count = _redact_node(state, data)
    unique = sorted({text for text in state.literals if len(text) >= SWEEP_MINIMUM}, key=len, reverse=True)
    swept, more = _sweep(redacted, unique, frozenset(unique)) if unique else (redacted, 0)
    if warnings is not None:
        warnings.extend(state.warnings)
    return swept, count + more


def testbed_text(data: Any, snapshot_id: str) -> str:
    """The redacted testbed as the archive holds it: the header, then the tree as YAML."""
    header = TESTBED_HEADER.format(version=__version__, snapshot_id=snapshot_id, marker=REDACTION_MARKER)
    return header + yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def find_testbed(manifest: dict[str, Any], testbed: Path | str | None = None) -> Path:
    """The testbed to export: the one given, else the one the manifest names if it is there."""
    if testbed is not None and str(testbed):
        path = Path(testbed)
        if not path.is_file():
            raise ExportRefused(
                f"the testbed {path} is not there. Pass --testbed with the testbed this run was "
                f"collected with; it is exported with every credential replaced"
            )
        return path
    recorded = manifest.get("testbed")
    if isinstance(recorded, str) and recorded and Path(recorded).is_file():
        return Path(recorded)
    where = f"names {recorded}, which is not there" if recorded else "names no testbed"
    raise ExportRefused(
        f"no testbed to export: the manifest {where}. Pass --testbed with the testbed this run "
        f"was collected with; it is exported with every credential replaced"
    )


def yaml_problem(exc: BaseException) -> str:
    """What PyYAML found wrong and where, without the text it found it in.

    The line a hand-written testbed fails to parse on is often its password
    line (a `: ` or a leading `@` in the password, a quote left open), and
    PyYAML's message quotes it. The refusal is printed on the prospect's
    screen and may be pasted into an email, so it carries the problem and
    the line and column only; the file is read as a stream besides, as pyATS
    reads it, so that the error holds no copy of the text at all.
    """
    if isinstance(exc, UnicodeDecodeError):
        return f"it is not UTF-8 text ({exc.reason})"
    problem = getattr(exc, "problem", None) or getattr(exc, "reason", None) or type(exc).__name__
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    if mark is not None:
        return f"{problem}, at line {mark.line + 1}, column {mark.column + 1}"
    position = getattr(exc, "position", None)
    return f"{problem}, at character {position + 1}" if isinstance(position, int) else str(problem)


def _load_testbed(path: Path) -> tuple[Any, list[str]]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError as exc:
        raise ExportRefused(f"the testbed {path} could not be read: {exc}") from exc
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ExportRefused(f"the testbed {path} could not be read as YAML: {yaml_problem(exc)}") from exc
    if not isinstance(data, dict):
        raise ExportRefused(f"the testbed {path} is not a mapping of testbed and devices")
    warnings = []
    if "extends" in data:
        warnings.append(
            f"the testbed {path} extends {data['extends']!r}: only this file is exported, so "
            f"what it takes from the file it extends is not in the archive"
        )
    return data, warnings


# --------------------------------------------------------------------------
# Writing the archive
# --------------------------------------------------------------------------


def _open_regular(path: Path) -> BinaryIO:
    """Open a file for reading without following a symlink, refusing anything but a regular file.

    O_NONBLOCK, because opening a named pipe for reading waits for a writer:
    a file swapped for one after it was checked would hang the export at
    the open, before fstat could refuse it. A regular file reads the same.
    """
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ExportRefused(f"{path} is not a regular file")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _digest_stream(handle: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := handle.read(CHUNK):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def file_sha256(path: Path | str) -> str:
    with Path(path).open("rb") as handle:
        return _digest_stream(handle)[0]


@dataclass
class _Member:
    name: str
    size: int
    sha256: str
    opener: Callable[[], BinaryIO]


def _bytes_member(name: str, data: bytes) -> _Member:
    return _Member(name, len(data), hashlib.sha256(data).hexdigest(), lambda: io.BytesIO(data))


def _file_member(name: str, path: Path) -> _Member:
    with _open_regular(path) as handle:
        sha256, size = _digest_stream(handle)
    return _Member(name, size, sha256, lambda: _open_regular(path))


class _HashingReader:
    """A file read through SHA-256 on its way into the tar, so what went in is what was hashed."""

    def __init__(self, handle: BinaryIO):
        self._handle = handle
        self._digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self._handle.read(size)
        self._digest.update(data)
        return data

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def _write_archive(output: Path, members: list[_Member], mtime: int) -> None:
    """The members, sorted, into a deterministic tar.gz at ``output``, through a temporary file renamed into place.

    The temporary file is beside the output, so the rename is atomic and an
    interrupted export leaves no half archive under the name a prospect
    would send. Its name ends with the archive's own, so the .gitignore
    line that keeps `*.export.tar.gz` out of a repository keeps it out too.
    Created 0600 by mkstemp and left so: the archive holds a network's
    collection, and the prospect, not the machine's other users, sends it.
    """
    if not output.parent.is_dir():
        raise ExportRefused(f"{output.parent} is not a directory to write the archive into")
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".", suffix=f".{output.name}", dir=output.parent)
    except OSError as exc:
        raise ExportRefused(f"could not write into {output.parent}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb") as raw:
            # No name and no time in the gzip header: both differ between two
            # exports of the same snapshot, and nothing reads them.
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as packed:
                with tarfile.open(fileobj=packed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                    for member in sorted(members, key=lambda item: item.name):
                        info = tarfile.TarInfo(member.name)
                        info.size = member.size
                        info.mode = 0o644
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = mtime
                        info.type = tarfile.REGTYPE
                        # Opened inside the try: a file removed, or swapped
                        # for a link or a pipe, after it was hashed fails to
                        # open (FileNotFoundError, ELOOP from O_NOFOLLOW, or
                        # _open_regular's own refusal), and that is the same
                        # refusal as one that shrank.
                        try:
                            with member.opener() as source:
                                reader = _HashingReader(source)
                                tar.addfile(info, reader)
                        except (OSError, ExportRefused) as exc:
                            raise ExportRefused(
                                f"{member.name} changed while it was being exported ({exc}); "
                                f"export again once nothing is writing to the snapshot"
                            ) from exc
                        if reader.hexdigest() != member.sha256:
                            raise ExportRefused(
                                f"{member.name} changed while it was being exported; export again "
                                f"once nothing is writing to the snapshot"
                            )
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(temporary, output)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _filename_part(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._") or "estate"


def default_archive_name(snapshot_id: str, estate: str | None) -> str:
    """`<estate>-<snapshot_id>.export.tar.gz`, or `<snapshot_id>.export.tar.gz` for a run of no estate."""
    stem = f"{_filename_part(estate)}-{snapshot_id}" if estate else snapshot_id
    return stem + ARCHIVE_SUFFIX


# --------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------


@dataclass
class ExportResult:
    """What `export` wrote, and what the prospect should be told about it."""

    path: Path
    snapshot_id: str
    estate: str | None
    size: int
    sha256: str
    member_count: int
    collected_files: int
    redacted_values: int
    testbed_source: Path
    left_out: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    synthetic: bool = False
    synthetic_notice: str | None = None
    signed: bool = False
    public_key_line: str | None = None
    key_path: Path | None = None
    key_created: bool = False
    export_manifest: dict[str, Any] = field(default_factory=dict)


def _read_manifest(root: Path) -> tuple[bytes, dict[str, Any]]:
    path = root / MANIFEST_NAME
    if not path.is_file() or path.is_symlink():
        raise ExportRefused(f"{root} is not a snapshot directory: it has no {MANIFEST_NAME}")
    try:
        with _open_regular(path) as handle:
            data = handle.read()
        # Read as verify will read it in the archive (load_json), so that a
        # manifest verify would refuse is refused here, with nothing written.
        manifest = load_json(data)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ExportRefused(f"{path} could not be read as JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ExportRefused(f"{path} is not a collection manifest")
    return data, manifest


def _check_named(root: Path, relative: Any) -> tuple[str | None, bool]:
    """Why a file the manifest names cannot go into the archive (None when it can), and whether it is missing."""
    problem = _path_problem(relative)
    if problem:
        return problem, False
    kind = forbidden_kind(relative)
    if kind:
        return f"is {kind}, which an export never carries", False
    if not collected_file_shape(relative):
        return "is not of the shape a run writes (<device>/raw/<name>.txt or <device>/state/<name>.json)", False
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            return "is a symlink" if current == root / relative else f"passes through a symlink ({part})", False
    target = root / relative
    if not target.exists():
        return None, True
    # No test reaches this line, and none can while the two checks above
    # stand: every part on the way is refused if it is a link, and `..` is
    # refused by _path_problem, so nothing left can lead out. It stays so
    # that a later change to either check cannot open a way out unnoticed.
    if not target.resolve().is_relative_to(root.resolve()):
        return "resolves outside the snapshot", False
    if not stat.S_ISREG(target.lstat().st_mode):
        return "is not a regular file", False
    return None, False


def _left_out(root: Path, named: set[str]) -> list[str]:
    """Files in a device's raw/ or state/ that the manifest does not name: reported, never read, never packed."""
    found = []
    for device in sorted(root.iterdir()):
        if device.is_symlink() or not device.is_dir():
            continue
        for folder in FOLDER_SUFFIXES:
            directory = device / folder
            if directory.is_symlink() or not directory.is_dir():
                continue
            for path in sorted(directory.rglob("*")):
                relative = path.relative_to(root).as_posix()
                if relative not in named and (path.is_file() or path.is_symlink()):
                    found.append(relative)
    return found


def recorded_allowlist(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """The allowlist as the collection manifest records it, in the export manifest's form; None when it records none.

    A run, or a merge whose every source was held to the same allowlist,
    records one hash (`commands_sha256`): "at collection". A merge whose
    sources differ, or of which one recorded none, has no such hash, and
    each source's is kept in its merged_from entry: "per source", every
    hash under its run's snapshot id, null for a run that recorded none.
    Export writes this and verify derives it again from manifest.json, so
    the two cannot disagree about what the manifest says.
    """
    recorded = manifest.get("commands_sha256")
    if recorded is not None:
        return {"sha256": recorded, "recorded": "at collection"}
    sources = merge_sources(manifest) or []
    if any(source["commands_sha256"] is not None for source in sources):
        per_source = {source["snapshot_id"]: source["commands_sha256"] for source in sources}
        return {"sha256": None, "recorded": "per source", "per_source": per_source}
    return None


def _allowlist_record(manifest: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Which allowlist the run was held to: its hash as the run, or each merged run, recorded it, or as hashed now."""
    record = recorded_allowlist(manifest)
    if record is not None and record["recorded"] == "at collection":
        recorded = record["sha256"]
        if not isinstance(recorded, str) or not SHA256_HEX.fullmatch(recorded):
            raise ExportRefused(
                f"the manifest's commands_sha256 ({str(recorded)[:80]!r}) is not a SHA-256: a "
                f"collector writes one lowercase hex digest there, so the manifest was edited"
            )
        return record, []
    if record is not None:
        warnings = []
        for source, recorded in record["per_source"].items():
            if recorded is None:
                # A source that is itself a merge records the hash its runs
                # share, and null when they were held to different ones: its
                # runs recorded theirs, so "recorded none" alone would be
                # untrue of it. merged_from does not say which a source is.
                warnings.append(
                    f"merged run {source or '?'} recorded no hash of its allowlist, or is itself a merge of runs "
                    f"held to different ones: which allowlist it was held to is not known, and verify cannot "
                    f"compare it"
                )
            elif not SHA256_HEX.fullmatch(recorded):
                raise ExportRefused(
                    f"merged run {source or '?'}'s commands_sha256 in merged_from ({recorded[:80]!r}) is not "
                    f"a SHA-256: a merge copies the one lowercase hex digest its source wrote, so the "
                    f"manifest was edited"
                )
        distinct = {recorded for recorded in record["per_source"].values() if recorded is not None}
        if len(distinct) > 1:
            warnings.append(
                f"the merged runs were held to {len(distinct)} different allowlists; the archive records each "
                f"run's, and verify compares every one with the allowlist it is given"
            )
        return record, warnings
    named = manifest.get("commands_file")
    path = Path(named) if isinstance(named, str) and named and Path(named).is_file() else DEFAULT_COMMANDS_FILE
    try:
        digest = file_sha256(path)
    except OSError as exc:
        raise ExportRefused(f"could not read the allowlist {path} to hash it: {exc}") from exc
    warning = (
        f"this run's collector recorded no hash of its allowlist, so {path} was hashed now, at "
        f"export: the archive shows which allowlist this machine has, not which one the run read"
    )
    return {"sha256": digest, "recorded": "at export", "file": str(path)}, [warning]


def _destination(output: Path | str | None, default: Path, name: str) -> Path:
    """The file the archive is written to: ``output``, or the default name inside it when it is a directory.

    An --output that ends with a path separator is a directory, whether or
    not it is there yet. Path() drops the separator, and `exports/` with no
    exports/ beside it became a file called `exports`, outside the
    .gitignore line that keeps `*.export.tar.gz` out of a repository. So a
    directory meant and not there is refused rather than guessed at, and so
    is a name that is there and is neither a directory nor a regular file
    (a device such as /dev/null, which the rename into place would replace).
    """
    if output is None:
        return default
    text = str(output)
    path = Path(text)
    if text.endswith(tuple(separator for separator in ("/", os.sep, os.altsep) if separator)):
        if not path.is_dir():
            raise ExportRefused(
                f"the output {text} names a directory, and there is none there: create it first, or "
                f"give the archive's file name"
            )
        return path / name
    if path.is_dir():
        return path / name
    if path.exists() and not stat.S_ISREG(path.stat().st_mode):
        raise ExportRefused(
            f"the output {text} is there and is not a regular file; name a file to write the archive to"
        )
    return path


def _testbed_mismatch(manifest: dict[str, Any], testbed: dict[str, Any], path: Path) -> list[str]:
    """A warning when the testbed names none of the run's devices: it may be another network's.

    The testbed comes from --testbed, the estate the shell names, or the
    path the manifest recorded, which is relative to wherever the collect
    ran; any of them can be the wrong network's, and its device names,
    addresses and usernames would then go out labelled as this run's. A
    device is matched by the name the manifest keys it by and, for a device
    renamed from a placeholder to the hostname it gave, by its testbed_name.
    """
    devices = manifest.get("devices") if isinstance(manifest.get("devices"), dict) else {}
    ran = {str(name) for name in devices} | {
        str(entry["testbed_name"]) for entry in devices.values()
        if isinstance(entry, dict) and entry.get("testbed_name")
    }
    listed = testbed.get("devices") if isinstance(testbed.get("devices"), dict) else {}
    if not ran or ran & {str(name) for name in listed}:
        return []
    return [
        f"the testbed {path} names none of this run's {len(devices)} device(s): it may belong to another "
        f"network. Check that it is the testbed this run was collected with, and pass --testbed with "
        f"that one if it is not"
    ]


def export_snapshot(
    snapshot: Path | str,
    *,
    testbed: Path | str | None = None,
    output: Path | str | None = None,
    sign: bool = False,
    key_path: Path | str | None = None,
    exported_at: datetime | None = None,
) -> ExportResult:
    """Pack one snapshot into a `.export.tar.gz`; ExportRefused, with nothing written, when it cannot be.

    ``exported_at`` is for tests, which need two exports to be the same bytes;
    otherwise it is now.
    """
    root = Path(snapshot).resolve()
    if not root.is_dir():
        raise ExportRefused(f"{snapshot} is not a snapshot directory")
    manifest_bytes, manifest = _read_manifest(root)
    snapshot_id = str(manifest.get("snapshot_id") or root.name)
    if not _safe_snapshot_id(snapshot_id):
        raise ExportRefused(f"the manifest's snapshot_id {snapshot_id!r} cannot name a folder")
    summary = collection_summary({**manifest, "snapshot_id": snapshot_id})
    created = _instant(manifest.get("created_at"))
    if created is None:
        raise ExportRefused(f"{root / MANIFEST_NAME} records no readable created_at: it is no collection manifest")
    # The one time every member carries: when the collection began, which
    # for a merge is its earliest source.
    started = collection_start(manifest) or created

    # Every file the manifest names, held to the rules before anything is read.
    refusals: list[str] = []
    missing: list[str] = []
    named: dict[str, Path] = {}
    for device, command, relative in named_files(manifest):
        problem, absent = _check_named(root, relative)
        where = f"{relative!r} (named for {device}'s {command!r})"
        if problem:
            refusals.append(f"{where} {problem}")
        elif absent:
            missing.append(str(relative))
        else:
            named[str(relative)] = root / relative
    if missing and store.files_pruned(root, manifest):
        raise ExportRefused(
            f"the per-command files of {snapshot_id} are not on disk: the run was pruned into the "
            f"estate database (collect --db-only), which holds them now. An export needs them on "
            f"disk; export a run whose files were kept"
        )
    if missing:
        shown = ", ".join(missing[:5]) + (f" and {len(missing) - 5} more" if len(missing) > 5 else "")
        refusals.append(f"{len(missing)} file(s) the manifest names are missing: {shown}")
    if refusals:
        listed = "\n".join(f"  - {line}" for line in refusals[:20])
        more = f"\n  - and {len(refusals) - 20} more" if len(refusals) > 20 else ""
        raise ExportRefused(f"{snapshot_id} cannot be exported as it stands:\n{listed}{more}")

    # Where it goes, settled before anything is created: a refusal from here
    # on must not leave a new signing key behind it either.
    name = default_archive_name(snapshot_id, summary["estate"])
    destination = _destination(output, root.parent / name, name)
    if destination.resolve().is_relative_to(root):
        raise ExportRefused(f"{destination} is inside the snapshot it exports; write the archive somewhere else")
    if not destination.parent.is_dir():
        raise ExportRefused(f"{destination.parent} is not a directory to write the archive into")

    testbed_path = find_testbed(manifest, testbed)
    testbed_data, warnings = _load_testbed(testbed_path)
    warnings += _testbed_mismatch(manifest, testbed_data, testbed_path)
    try:
        redacted, redacted_values = redact_testbed(testbed_data, warnings)
    except RecursionError as exc:
        raise ExportRefused(f"the testbed {testbed_path} refers to itself and cannot be written out") from exc
    except OversizedTestbed as exc:
        raise OversizedTestbed(f"the testbed {testbed_path} {exc}") from exc
    testbed_bytes = testbed_text(redacted, snapshot_id).encode("utf-8")
    allowlist, allowlist_warnings = _allowlist_record(manifest)
    warnings += allowlist_warnings
    if not summary["collection"]["finished_recorded"]:
        warnings.append(
            "the manifest records no finish time (a collector older than this one wrote it)"
            if summary["sources"] is None else
            "the merge records no finish time: at least one of its runs recorded none (a collector older "
            "than this one made it)"
        )

    top = PurePosixPath(snapshot_id)
    members = [
        _bytes_member(str(top / MANIFEST_NAME), manifest_bytes),
        _bytes_member(str(top / TESTBED_NAME), testbed_bytes),
    ]
    try:
        members += [_file_member(str(top / relative), path) for relative, path in sorted(named.items())]
    except OSError as exc:
        raise ExportRefused(f"could not read a file of {snapshot_id}: {exc}") from exc

    moment = exported_at or datetime.now(timezone.utc)
    document = {
        "format": EXPORT_FORMAT,
        "format_version": EXPORT_FORMAT_VERSION,
        "exported_at": _utc_text(moment),
        "exported_by": {"tool": "netstate", "version": __version__},
        **summary,
        "allowlist": allowlist,
        "testbed": {"file": str(top / TESTBED_NAME), "redacted_values": redacted_values},
        "files": {member.name: {"sha256": member.sha256, "bytes": member.size} for member in members},
    }
    document_bytes = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
    members.append(_bytes_member(str(top / EXPORT_MANIFEST_NAME), document_bytes))

    key = None
    if sign or key_path is not None:
        try:
            key = signing.load_or_create(key_path)
            members.append(_bytes_member(str(top / SIGNATURE_NAME), signing.signature_document(key, document_bytes)))
        except signing.SigningError as exc:
            raise ExportRefused(str(exc)) from exc

    _write_archive(destination, members, int(started.timestamp()))
    return ExportResult(
        path=destination,
        snapshot_id=snapshot_id,
        estate=summary["estate"],
        size=destination.stat().st_size,
        sha256=file_sha256(destination),
        member_count=len(members),
        collected_files=len(named),
        redacted_values=redacted_values,
        testbed_source=testbed_path,
        left_out=_left_out(root, set(named)),
        warnings=warnings,
        synthetic=summary["synthetic"],
        synthetic_notice=summary["synthetic_notice"],
        signed=key is not None,
        public_key_line=key.line if key is not None else None,
        key_path=key.path if key is not None else None,
        key_created=key.created if key is not None else False,
        export_manifest=document,
    )


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------


@dataclass
class VerifyReport:
    """What `verify` found. ``ok`` only with no problem; ``readable`` False when it was no gzip tar at all."""

    path: Path
    ok: bool = False
    readable: bool = True
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Seen:
    name: str
    type: bytes
    size: int
    sha256: str | None = None
    data: bytes | None = None
    too_large: bool = False


def _kept(name: str) -> bool:
    """The members verify reads as well as hashes: the two manifests, the signature and the testbed."""
    parts = name.split("/")
    return len(parts) == 2 and parts[1] in TOP_LEVEL_NAMES


class _Recorded:
    """The decompressed archive as tarfile reads it, keeping its last few reads.

    tarfile reads in records of 10 KB, and the block it found the end in
    (or stopped at) lies within the last two reads; four are kept.
    """

    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle
        self._recent: collections.deque[tuple[int, bytes]] = collections.deque(maxlen=4)
        self.position = 0

    def read(self, size: int = -1) -> bytes:
        data = self._handle.read(size)
        self._recent.append((self.position, data))
        self.position += len(data)
        return data

    def read_since(self, offset: int) -> bytes:
        """What has been read from ``offset`` on, of what is kept."""
        return b"".join(
            data[max(0, offset - start):] for start, data in self._recent if start + len(data) > offset
        )


def _after_the_end(stream: _Recorded, end: int) -> str | None:
    """What follows the tar's last member, when it is more than zero padding; None when it is not.

    tarfile stops at the first block that is no header, an end-of-archive
    block of zeros or anything else, and reads no further. What lies past
    it went unchecked and is still in the file: a second tar archive after
    the end blocks, or a second gzip member holding one, is unpacked by
    `tar --ignore-zeros`, and bytes after the gzip stream travel with the
    archive unseen. An export ends with zero blocks and nothing after them,
    so the rest is read to its end: zeros pass, anything else is named, as
    is a gzip stream cut short or failing its CRC there, which the
    archive's members alone never showed.
    """
    try:
        rest = stream.read_since(end)
        while rest:
            if rest.strip(b"\0"):
                return (
                    "holds data after the end of its tar archive, where an export holds only zero padding: "
                    "a tar that reads on past the end (tar --ignore-zeros) unpacks it, and verify has not checked it"
                )
            rest = stream.read(CHUNK)
    except (OSError, EOFError, zlib.error) as exc:
        return (
            f"has a gzip stream that is damaged or cut short after the end of its tar archive ({exc}): it is "
            f"not the file export wrote"
        )
    return None


def _read_members(path: Path) -> tuple[list[_Seen], list[str]]:
    """Every entry of the archive in order, each regular file hashed as it streams past; nothing is written to disk.

    And what is wrong with the archive as a whole, each said as the end of
    a sentence that begins with its path: what follows the tar's end, when
    it is more than zero padding (see _after_the_end), and a global pax
    header. GzipFile rather than tarfile's own "r|gz": it reads every gzip
    member, checks each one's CRC, and refuses bytes after the last one
    that are not gzip, where tarfile's stream stops at the end of the first
    member and checks nothing.
    """
    seen: list[_Seen] = []
    whole: list[str] = []
    with path.open("rb") as raw, gzip.GzipFile(fileobj=raw, mode="rb") as packed:
        stream = _Recorded(packed)
        with tarfile.open(fileobj=stream, mode="r|") as tar:  # type: ignore[call-overload]
            for info in tar:
                seen.append(_read_entry(tar, info))
            after = _after_the_end(stream, tar.offset)
            # A global header's records (a path, a size) apply to every
            # member after it, and tar programs differ in which they apply:
            # the members one of them unpacks need not be the ones verify
            # read. export writes none (_write_archive gives no pax_headers).
            if tar.pax_headers:
                whole.append(
                    f"holds a global pax header ({_short(sorted(tar.pax_headers))}), which export never writes "
                    f"and tar programs apply differently"
                )
    if after:
        whole.append(after)
    return seen, whole


def _read_entry(tar: tarfile.TarFile, info: tarfile.TarInfo) -> _Seen:
    """One entry: its name and type, and a regular file's hash and size (its bytes too when verify reads them)."""
    # A pax header can mark a regular file sparse (GNU.sparse.*): tarfile
    # then expands it, and a tar that does not know the convention writes
    # out the map. No export holds one, so it is a sparse file, not a
    # regular one.
    entry = _Seen(name=info.name, type=tarfile.GNUTYPE_SPARSE if info.issparse() else info.type, size=info.size)
    if entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
        return entry
    handle = tar.extractfile(info)
    digest = hashlib.sha256()
    keep = bytearray() if _kept(info.name) else None
    while handle is not None and (chunk := handle.read(CHUNK)):
        digest.update(chunk)
        if keep is not None:
            if len(keep) + len(chunk) > KEEP_LIMIT:
                entry.too_large = True
                keep = None
            else:
                keep.extend(chunk)
    entry.sha256 = digest.hexdigest()
    entry.data = bytes(keep) if keep is not None else None
    return entry


ENTRY_KINDS = {
    tarfile.DIRTYPE: "a directory",
    tarfile.SYMTYPE: "a symlink",
    tarfile.LNKTYPE: "a hard link",
    tarfile.CHRTYPE: "a character device",
    tarfile.BLKTYPE: "a block device",
    tarfile.FIFOTYPE: "a FIFO",
    tarfile.CONTTYPE: "a contiguous file",
    tarfile.GNUTYPE_SPARSE: "a sparse file",
}


def _member_problems(entries: list[_Seen], top: str) -> list[str]:
    problems = []
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.name] = counts.get(entry.name, 0) + 1
    for name, count in counts.items():
        if count > 1:
            problems.append(f"{name} appears {count} times in the archive; an export holds each file once")
    reported: set[str] = set()
    for entry in entries:
        name = entry.name
        if name in reported:
            continue
        reported.add(name)
        if entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
            kind = ENTRY_KINDS.get(entry.type, f"an entry of type {entry.type!r}")
            problems.append(f"{name} is {kind}, not a regular file: an export holds regular files only")
            continue
        problem = _path_problem(name)
        if problem:
            problems.append(f"{name} {problem}")
            continue
        if not name.startswith(f"{top}/"):
            problems.append(f"{name} is outside the archive's folder {top}/")
            continue
        relative = name[len(top) + 1:]
        kind = forbidden_kind(relative)
        if kind:
            problems.append(f"{name} is {kind}, which an export never carries")
        elif not member_shape(relative):
            problems.append(
                f"{name} is not a file an export holds (manifest.json, testbed.yaml, the export "
                f"manifest and its signature, <device>/raw/*.txt and <device>/state/*.json)"
            )
    return problems


def export_manifest_keys() -> frozenset[str]:
    """The top-level keys export_snapshot writes into an export manifest: its own, then the collection summary's."""
    own = {"format", "format_version", "exported_at", "exported_by", "allowlist", "testbed", "files"}
    return frozenset(own | set(collection_summary({})))


def _case_collisions(regular: dict[str, _Seen]) -> list[str]:
    """A warning for each name that is another's but for case or Unicode form.

    On a file system that ignores case, as macOS's and Windows's do by
    default (and macOS's ignores how an accented letter is composed), the
    two are one file once unpacked: one overwrites the other, and what the
    owner reads is not all that was verified. A run on Linux can write
    both, from two devices whose testbed names differ only in case, so it
    is said rather than refused.
    """
    first: dict[str, str] = {}
    warnings = []
    for name in regular:
        folded = unicodedata.normalize("NFC", name).casefold()
        if folded in first:
            warnings.append(
                f"{name} and {first[folded]} differ only in case or Unicode form: unpacked on a file system "
                f"that ignores case (macOS, Windows) one overwrites the other, so unpack the archive on Linux"
            )
        else:
            first[folded] = name
    return warnings


def _short(value: Any, limit: int = 120) -> str:
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _summary_problems(stated: dict[str, Any], derived: dict[str, Any]) -> list[str]:
    """Where the export manifest's summary differs from the summary of the manifest.json it carries."""
    problems = []
    for key, value in derived.items():
        said = stated.get(key)
        if said == value:
            continue
        if key == "devices" and isinstance(said, dict):
            for name in sorted(set(value) | set(said)):
                if name not in said:
                    problems.append(f"export-manifest.json leaves out device {name}, which manifest.json holds")
                elif name not in value:
                    problems.append(f"export-manifest.json names device {name}, which manifest.json does not hold")
                elif said[name] != value[name]:
                    stated_device = said[name] if isinstance(said[name], dict) else {}
                    for field_name in sorted(set(value[name]) | set(stated_device)):
                        theirs = stated_device.get(field_name)
                        if theirs != value[name].get(field_name):
                            problems.append(
                                f"export-manifest.json says {name}'s {field_name} is {_short(theirs)}, "
                                f"but manifest.json says {_short(value[name].get(field_name))}"
                            )
            continue
        problems.append(
            f"export-manifest.json says {key} is {_short(said)}, but manifest.json says {_short(value)}"
        )
    return problems


def _signature_check(
    report: VerifyReport, signature: _Seen | None, document: bytes | None, public_key: str | Path | None,
) -> dict[str, Any]:
    state: dict[str, Any] = {"signed": signature is not None, "valid": False, "kid": None, "compared": False}
    given = None
    # An empty --public-key is a key asked for and not given, as one that
    # cannot be read is: `--public-key "$SENDER_KEY"` with the variable
    # unset passed verify as "valid, not compared" and exited 0.
    if public_key is not None and not str(public_key).strip():
        report.problems.append(
            "the --public-key given is empty: pass the sender's key line, or a file holding it, to "
            "compare the signature with"
        )
    if public_key is not None and str(public_key).strip():
        try:
            given = signing.read_public_key(public_key)
            state["given_kid"] = signing.key_id(given)
        except signing.SigningError as exc:
            report.problems.append(f"the --public-key given cannot be used: {exc}")
    if signature is None:
        if public_key is not None and str(public_key).strip():
            report.problems.append(
                "a public key was given, but the archive is not signed: it cannot be shown to come "
                "from the holder of that key"
            )
        else:
            report.warnings.append(
                "the archive is not signed: its hashes show it is whole and consistent, not who made it"
            )
        return state
    if signature.data is None or document is None:
        report.problems.append("the signature cannot be checked: the export manifest or the signature is unreadable")
        return state
    # Held to the form export writes before signing reads it: signing
    # takes the three keys it knows and ignores any other, and a key held
    # twice is read as its last. Nothing hashes this member.
    try:
        written = load_json(signature.data)
    except (UnicodeDecodeError, ValueError) as exc:
        report.problems.append(f"the signature cannot be checked: {SIGNATURE_NAME} is not JSON as export writes it: {exc}")
        return state
    if isinstance(written, dict) and set(written) != SIGNATURE_KEYS:
        report.problems.append(
            f"the signature cannot be checked: {SIGNATURE_NAME} holds the keys {_short(sorted(written))}, not "
            f"the {_short(sorted(SIGNATURE_KEYS))} export writes"
        )
        return state
    try:
        parsed = signing.read_signature(signature.data)
        state["kid"] = parsed.kid
        state["public_key"] = parsed.line
        state["valid"] = signing.verify(parsed.public, parsed.signature, document)
    except signing.SigningError as exc:
        report.problems.append(f"the signature cannot be checked: {exc}")
        return state
    if not state["valid"]:
        report.problems.append(
            f"the signature by key {parsed.kid} does not verify: export-manifest.json, or the "
            f"signature, was changed after the archive was signed"
        )
    if given is not None:
        state["compared"] = True
        if given != parsed.public:
            report.problems.append(
                f"the archive is signed by key {parsed.kid}, not by the key given ({signing.key_id(given)}): "
                f"it is not from the sender whose key you hold"
            )
    elif state["valid"]:
        report.warnings.append(
            f"signed by key {parsed.kid}, but that key was NOT compared with a key received separately: "
            f"anyone can sign an archive. Pass --public-key with the line the sender gave you by "
            f"phone, text or a separate email"
        )
    return state


def verify_archive(
    path: Path | str, public_key: str | Path | None = None, allowlist: Path | str | None = None,
) -> VerifyReport:
    """Check an export in place, without extracting it; the report says what holds and what does not.

    ``public_key`` is the sender's key line, or a file holding it, received
    by a channel other than the archive's. ``allowlist`` is the allowlist the
    collection is compared with (default: the one installed with netstate).

    Never raises. The archive is someone else's file, and whatever it holds
    is either reported as a problem or, failing that, as the one problem
    that it could not be checked: a traceback in place of a FAILED report
    tells the owner nothing and looks like DiscoNet's fault.
    """
    path = Path(path)
    report = VerifyReport(path=path)
    try:
        _verify_into(report, path, public_key, allowlist)
    except Exception as exc:  # noqa: BLE001 - see the docstring
        report.problems.append(f"the archive could not be checked: {type(exc).__name__}")
    report.ok = not report.problems
    return report


def _verify_into(
    report: VerifyReport, path: Path, public_key: str | Path | None, allowlist: Path | str | None,
) -> None:
    if not path.is_file():
        report.readable = False
        report.problems.append(f"{path} is not there" if not path.exists() else f"{path} is not a file")
        return
    try:
        report.summary["archive"] = {"file": str(path), "sha256": file_sha256(path), "bytes": path.stat().st_size}
        entries, whole = _read_members(path)
    except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
        report.readable = False
        report.problems.append(f"{path} is not a readable gzip-compressed tar archive ({exc})")
        return
    if not entries:
        report.readable = False
        report.problems.append(f"{path} is an empty archive")
        return
    report.problems.extend(f"{path} {problem}" for problem in whole)

    regular = {entry.name: entry for entry in entries if entry.type in (tarfile.REGTYPE, tarfile.AREGTYPE)}
    candidates = [
        entry for entry in entries
        if entry.name.count("/") == 1 and entry.name.endswith(f"/{EXPORT_MANIFEST_NAME}")
    ]
    document: dict[str, Any] = {}
    document_bytes = None
    top = entries[0].name.split("/", 1)[0]
    if not candidates:
        report.problems.append(f"the archive holds no {EXPORT_MANIFEST_NAME}: it is not a DiscoNet export")
    else:
        # The last, as `regular` holds the last of every name: tar unpacks a
        # name twice over itself, so the last is what lands on disk, and
        # the hashes, the signature and the summary all read those bytes.
        # A name held twice is a problem of its own (_member_problems).
        found = candidates[-1]
        top = found.name.split("/", 1)[0]
        document_bytes = found.data
        try:
            loaded = load_json(found.data or b"")
            document = loaded if isinstance(loaded, dict) else {}
            if not isinstance(loaded, dict):
                report.problems.append(f"{found.name} is not a JSON object")
        except (UnicodeDecodeError, ValueError) as exc:
            report.problems.append(f"{found.name} is not readable JSON: {exc}")
    if document:
        # The export manifest is a format of one version, and what it holds
        # beyond what export writes is a statement verify checks nothing of
        # (an `"approved": true` read by eye), or a place to carry anything.
        for key in sorted(set(document) - export_manifest_keys()):
            report.problems.append(f"the export manifest holds {_short(key)}, which export does not write")
        if document.get("format") != EXPORT_FORMAT or document.get("format_version") != EXPORT_FORMAT_VERSION:
            report.problems.append(
                f"the export manifest is format {document.get('format')!r} version "
                f"{document.get('format_version')!r}; this verify reads {EXPORT_FORMAT!r} version "
                f"{EXPORT_FORMAT_VERSION}"
            )
        stated_id = document.get("snapshot_id")
        if not _safe_snapshot_id(stated_id):
            report.problems.append(f"the export manifest's snapshot_id {_short(stated_id)} cannot name a folder")
        elif stated_id != top:
            report.problems.append(f"the export manifest names snapshot {stated_id}, but sits in the folder {top}/")

    report.problems.extend(_member_problems(entries, top))
    for entry in entries:
        if entry.too_large:
            report.problems.append(f"{entry.name} is too large for verify to read")

    # Every member against its listed hash, and the list against the members.
    files = document.get("files") if isinstance(document.get("files"), dict) else None
    own = {f"{top}/{EXPORT_MANIFEST_NAME}", f"{top}/{SIGNATURE_NAME}"}
    hashes_ok = files is not None
    if document and files is None:
        report.problems.append("the export manifest lists no files")
    for name, listed in (files or {}).items():
        if name in own:
            report.problems.append(f"the export manifest lists {name}, which cannot carry its own hash")
            hashes_ok = False
            continue
        sha256 = listed.get("sha256") if isinstance(listed, dict) else None
        size = listed.get("bytes") if isinstance(listed, dict) else None
        member = regular.get(name)
        if member is None:
            report.problems.append(f"missing: {name} is listed in the export manifest but is not in the archive")
            hashes_ok = False
        # An int, as export writes it: `true` and `959.0` are equal to 1 and
        # 959 in Python, and are no size export ever wrote.
        elif member.sha256 != sha256 or type(size) is not int or member.size != size:
            report.problems.append(
                f"tampered: {name} does not match the export manifest (sha256 {member.sha256}, "
                f"{member.size} bytes; listed {sha256}, {size} bytes)"
            )
            hashes_ok = False
    unlisted = set()
    for name in regular:
        if name not in own and files is not None and name not in files:
            report.problems.append(f"extra: {name} is in the archive but not listed in the export manifest")
            unlisted.add(name)
            hashes_ok = False
    report.warnings.extend(_case_collisions(regular))

    # The summary, re-derived from the collection manifest the archive carries.
    manifest_entry = regular.get(f"{top}/{MANIFEST_NAME}")
    manifest: dict[str, Any] | None = None
    if manifest_entry is None:
        report.problems.append(f"the archive holds no {top}/{MANIFEST_NAME}")
    elif manifest_entry.data is not None:
        try:
            loaded = load_json(manifest_entry.data)
            manifest = loaded if isinstance(loaded, dict) else None
            if manifest is None:
                report.problems.append(f"{manifest_entry.name} is not a collection manifest")
        except (UnicodeDecodeError, ValueError) as exc:
            report.problems.append(f"{manifest_entry.name} is not readable JSON: {exc}")
    # A manifest with no snapshot_id is named by its folder, as export named it.
    derived = (
        collection_summary({**manifest, "snapshot_id": manifest.get("snapshot_id") or top})
        if manifest is not None else None
    )
    if derived is not None and document:
        report.problems.extend(_summary_problems(document, derived))
    if manifest is not None:
        named = set()
        for device, command, relative in named_files(manifest):
            problem = _path_problem(relative)
            if problem:
                report.problems.append(f"manifest.json names {relative!r} for {device}'s {command!r}, which {problem}")
                continue
            named.add(f"{top}/{relative}")
            if f"{top}/{relative}" not in regular:
                report.problems.append(
                    f"manifest.json names {relative} for {device}'s {command!r}, which is not in the archive"
                )
        # And the other way: export packs only the files manifest.json
        # names, so a collected file it does not name was added after, and
        # listing it in the export manifest with its true hash made it no
        # less extra. Nothing downstream reads it (the manifest is what
        # names a run's files), which is how it would go unseen.
        for name in regular:
            relative = name[len(top) + 1:] if name.startswith(f"{top}/") else ""
            if name not in named and name not in unlisted and collected_file_shape(relative):
                report.problems.append(f"extra: {name} is in the archive, but manifest.json names no such file")

    # The allowlist the run was held to, against the one the reader trusts.
    allowlist_state = _allowlist_check(report, document, manifest, allowlist)

    # The testbed: there, and with nothing left in it to redact.
    testbed_state = _testbed_check(report, document, regular, top)

    signature_state = _signature_check(
        report, regular.get(f"{top}/{SIGNATURE_NAME}"), document_bytes, public_key,
    )

    # Shown only from the manifest.json verify read, never from what the
    # export manifest says of it: that is the claim under test, and its
    # values are of whatever type its writer chose. With no manifest.json to
    # read, the summary is the empty one, and says so.
    shown = derived if derived is not None else collection_summary({})
    if derived is not None and not shown["collection"]["finished_recorded"]:
        report.warnings.append(
            "the collection's finish time is not recorded (a collector older than this one made it)"
            if shown["sources"] is None else
            "the merge's finish time is not recorded: at least one of its runs recorded none (a collector "
            "older than this one made it)"
        )
    if shown["synthetic"]:
        report.warnings.append(
            "this is the synthetic demonstration estate, not a collected network: "
            + (shown["synthetic_notice"] or "its manifest says so")
        )
    report.summary.update(shown)
    report.summary.update({
        "collection_read": derived is not None,
        "exported_at": document.get("exported_at"),
        "exported_by": document.get("exported_by"),
        "allowlist": allowlist_state,
        "testbed": testbed_state,
        "file_count": len(regular),
        "total_bytes": sum(entry.size for entry in regular.values()),
        "hashes_ok": hashes_ok,
        "signature": signature_state,
    })


def _allowlist_check(
    report: VerifyReport, document: dict[str, Any], manifest: dict[str, Any] | None, allowlist: Path | str | None,
) -> dict[str, Any]:
    record = document.get("allowlist") if isinstance(document.get("allowlist"), dict) else {}
    stated = record.get("sha256")
    recorded = record.get("recorded")
    reference = Path(allowlist) if allowlist is not None else DEFAULT_COMMANDS_FILE
    state: dict[str, Any] = {
        "sha256": stated, "recorded": recorded, "file": record.get("file"),
        "reference_file": str(reference), "reference_sha256": None, "matches": False,
    }
    if not document:
        return state
    expected = recorded_allowlist(manifest) if manifest is not None else None
    if recorded == "per source":
        return _per_source_check(report, record, manifest, expected, reference, state)
    usable = isinstance(stated, str) and bool(SHA256_HEX.fullmatch(stated))
    if not usable or recorded not in ("at collection", "at export"):
        report.problems.append("the export manifest records no usable allowlist hash")
        return state
    at_collection = manifest.get("commands_sha256") if manifest is not None else None
    if manifest is not None:
        if expected is not None and expected["recorded"] == "per source":
            report.problems.append(
                f"manifest.json records the allowlist per merged run, but the export manifest says one "
                f"hash was recorded {recorded}"
            )
        elif at_collection is not None and at_collection != stated:
            report.problems.append(
                f"manifest.json records the allowlist as sha256 {at_collection}, but the export "
                f"manifest says {stated}"
            )
        elif at_collection is not None and recorded != "at collection":
            report.problems.append(
                "the export manifest says the allowlist was hashed at export, but manifest.json "
                "recorded it at collection"
            )
        elif at_collection is None and recorded == "at collection":
            report.problems.append(
                "the export manifest says the allowlist was hashed at collection, but manifest.json "
                "records no hash of it"
            )
    try:
        state["reference_sha256"] = file_sha256(reference)
    except OSError as exc:
        report.problems.append(f"could not read the allowlist {reference} to compare with: {exc}")
        return state
    state["matches"] = state["reference_sha256"] == stated
    if not state["matches"]:
        report.problems.append(
            f"the allowlist hash recorded {recorded} (sha256 {stated}) does not match {reference} "
            f"(sha256 {state['reference_sha256']}): the run was not held to the allowlist you are "
            f"comparing with"
        )
    if recorded == "at export":
        report.warnings.append(
            "the allowlist was hashed when the snapshot was exported, not when it was collected: "
            "it shows which allowlist the exporting machine had, not which one the run read"
        )
    return state


def _per_source_check(
    report: VerifyReport, record: dict[str, Any], manifest: dict[str, Any] | None,
    expected: dict[str, Any] | None, reference: Path, state: dict[str, Any],
) -> dict[str, Any]:
    """A merge's allowlist, run by run: each hash against manifest.json's merged_from, then the reference.

    A run that recorded no hash cannot be compared and is warned about by
    name; one whose hash differs from the reference is a problem by name:
    the files it contributed were not collected under the allowlist the
    owner trusts.
    """
    per_source = record.get("per_source")
    state["per_source"] = per_source
    if manifest is not None:
        if expected is None or expected["recorded"] != "per source":
            said = "records one hash of it, at collection" if expected is not None else "records no hash of it"
            report.problems.append(
                f"the export manifest says the allowlist was recorded per merged run, but manifest.json {said}"
            )
        elif record.get("sha256") is not None or per_source != expected["per_source"]:
            report.problems.append(
                f"the export manifest's allowlist hashes per merged run, {_short(per_source)}, are not the ones "
                f"manifest.json's merged_from records, {_short(expected['per_source'])}"
            )
    if not isinstance(per_source, dict) or not any(isinstance(value, str) for value in per_source.values()):
        report.problems.append("the export manifest records no usable allowlist hash")
        return state
    try:
        state["reference_sha256"] = file_sha256(reference)
    except OSError as exc:
        report.problems.append(f"could not read the allowlist {reference} to compare with: {exc}")
        return state
    hashed = {source: value for source, value in per_source.items() if value is not None}
    for source, value in per_source.items():
        if value is None:
            # Worded as at export (_allowlist_record): a merge among the
            # sources is null here when its own runs differed.
            report.warnings.append(
                f"merged run {source or '?'} recorded no hash of its allowlist, or is itself a merge of runs "
                f"held to different ones, so what it collected cannot be compared with {reference}"
            )
        elif value != state["reference_sha256"]:
            report.problems.append(
                f"merged run {source or '?'} was held to the allowlist with sha256 {_short(value)}, which does "
                f"not match {reference} (sha256 {state['reference_sha256']}): what it collected was not "
                f"held to the allowlist you are comparing with"
            )
    state["sources"] = len(per_source)
    state["sources_recorded"] = len(hashed)
    state["matches"] = all(value == state["reference_sha256"] for value in hashed.values())
    return state


def _testbed_check(
    report: VerifyReport, document: dict[str, Any], regular: dict[str, _Seen], top: str,
) -> dict[str, Any]:
    record = document.get("testbed") if isinstance(document.get("testbed"), dict) else {}
    expected = f"{top}/{TESTBED_NAME}"
    state = {"file": record.get("file"), "redacted_values": record.get("redacted_values")}
    if not document:
        return state
    if record.get("file") != expected:
        report.problems.append(f"the export manifest names the testbed {_short(record.get('file'))}, not {expected}")
    member = regular.get(expected)
    if member is None:
        report.problems.append(f"the archive holds no testbed ({expected})")
        return state
    if member.data is None:
        return state
    try:
        data = yaml.safe_load(member.data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        report.problems.append(f"{expected} is not readable YAML: {yaml_problem(exc)}")
        return state
    try:
        _tree, left = redact_testbed(data)
    except RecursionError:
        report.problems.append(f"{expected} refers to itself: it is not the testbed export writes")
        return state
    except OversizedTestbed as exc:
        report.problems.append(f"{expected} {exc}")
        return state
    if left:
        report.problems.append(
            f"{expected} still holds {left} credential value(s) that are not replaced: it is not "
            f"the testbed export writes"
        )
    return state


def _size(count: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if count < 1024 or unit == "GB":
            return f"{count} {unit}" if unit == "bytes" else f"{count:.1f} {unit}"
        count /= 1024
    return f"{count} bytes"


def human_size(count: int) -> str:
    """A byte count as a person reads it: 1.2 MB."""
    return _size(int(count))


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def summary_lines(report: VerifyReport) -> list[str]:
    """The report as plain lines, for the console and for a file sent back to the prospect.

    Never raises. verify_archive builds every value shown from the archive
    with its type fixed, but a report is a plain dataclass anyone can fill;
    should a line still fail, the result and the problems are what must
    reach the reader, so they are given without the summary.

    Every line is one line of printable text (see _printable): the names
    and values in it are the archive's.
    """
    try:
        return [_printable(line) for line in _summary_lines(report)]
    except Exception as exc:  # noqa: BLE001 - see the docstring
        lines = [f"Archive:    {report.path}", f"Summary:    cannot be shown ({type(exc).__name__})"]
        lines.extend(f"Warning:    {warning}" for warning in report.warnings)
        if report.ok:
            lines.append("Result:     OK")
        else:
            lines.append(f"Result:     FAILED ({len(report.problems)} problem(s))")
            lines.extend(f"  - {problem}" for problem in report.problems)
        return [_printable(line) for line in lines]


def _printable(line: str) -> str:
    """``line`` with each control, format or line-separator character written as its escape (`\\x1b`, `\\n`, `\\u202e`).

    The summary is made of what the archive says: its member names, the
    estate, device and run names of its manifest.json. An escape sequence
    in one is a command to the owner's terminal (rich passes ESC through),
    a newline in one prints a line of its own such as `Result:     OK`, and
    a right-to-left override shows text in another order than it is.
    Written out, each says what it is.
    """
    return "".join(
        ascii(character)[1:-1] if unicodedata.category(character) in ("Cc", "Cf", "Zl", "Zp") else character
        for character in line
    )


def _collector_text(summary: dict[str, Any]) -> str:
    """`netstate 0.2.0`, or each version a merge's runs were collected by, or `?` for none recorded."""
    version = summary.get("collector_version")
    if version:
        return f"netstate {version}"
    versions = [str(text) for text in _sequence(summary.get("collector_versions"))]
    sources = _sequence(summary.get("sources"))
    unknown = any(not _mapping(source).get("collector_versions") for source in sources)
    if not versions:
        return "netstate ?" + (" (no merged run recorded its version)" if sources else "")
    return f"netstate {' and '.join(versions)}" + (" and runs that recorded none" if unknown else "")


def _summary_lines(report: VerifyReport) -> list[str]:
    summary = report.summary
    lines: list[str] = []
    archive = _mapping(summary.get("archive"))
    lines.append(f"Archive:    {report.path}")
    if archive:
        lines.append(f"            {human_size(archive.get('bytes') or 0)}, sha256 {archive.get('sha256')}")
    if not report.readable:
        lines.append("Result:     FAILED")
        lines.extend(f"  - {problem}" for problem in report.problems)
        return lines
    if summary.get("collection_read") is False:
        lines.append("Snapshot:   ? (the archive's manifest.json could not be read, so nothing about the "
                     "collection is shown)")
    else:
        estate = summary.get("estate")
        named = f" (estate {estate})" if estate else " (no estate named)"
        lines.append(f"Snapshot:   {summary.get('snapshot_id') or '?'}{named}")
        if summary.get("synthetic"):
            lines.append(f"DEMO:       {summary.get('synthetic_notice') or 'the synthetic demonstration estate'}")
        collection = _mapping(summary.get("collection"))
        finished = collection.get("finished_utc") or "finish not recorded"
        lines.append(
            f"Collected:  by {_collector_text(summary)}, "
            f"{collection.get('started_utc') or '?'} to {finished} (UTC)"
        )
    exporter = _mapping(summary.get("exported_by"))
    lines.append(f"Exported:   by netstate {exporter.get('version') or '?'} at {summary.get('exported_at') or '?'}")
    if summary.get("collection_read") is not False:
        lines.extend(_collection_lines(summary))
    allowlist = _mapping(summary.get("allowlist"))
    if allowlist.get("recorded") == "per source" and isinstance(allowlist.get("per_source"), dict):
        verdict = "all of them match" if allowlist.get("matches") else "NOT all of them match"
        lines.append(
            f"Allowlist:  recorded per merged run, {allowlist.get('sources_recorded', 0)} of "
            f"{allowlist.get('sources', len(allowlist['per_source']))} with a hash; {verdict} "
            f"{allowlist.get('reference_file')}"
        )
    elif allowlist.get("sha256"):
        verdict = "matches" if allowlist.get("matches") else "DOES NOT MATCH"
        lines.append(
            f"Allowlist:  sha256 {allowlist.get('sha256')} (recorded {allowlist.get('recorded')}), "
            f"{verdict} {allowlist.get('reference_file')}"
        )
    testbed = _mapping(summary.get("testbed"))
    if testbed.get("file"):
        lines.append(
            f"Testbed:    {testbed.get('file')}, {testbed.get('redacted_values')} credential value(s) replaced"
        )
    lines.append(
        f"Files:      {summary.get('file_count', 0)}, {human_size(summary.get('total_bytes') or 0)}; "
        + ("every hash matched" if summary.get("hashes_ok") else "NOT every hash matched")
    )
    signature = _mapping(summary.get("signature"))
    if not signature.get("signed"):
        lines.append("Signature:  not signed")
    elif not signature.get("valid"):
        lines.append(f"Signature:  INVALID (key {signature.get('kid') or '?'})")
    elif signature.get("compared"):
        same = signature.get("given_kid") == signature.get("kid")
        lines.append(
            f"Signature:  valid, key {signature.get('kid')}, "
            + ("the key you were given" if same else f"NOT the key you were given ({signature.get('given_kid')})")
        )
    else:
        lines.append(f"Signature:  valid, key {signature.get('kid')}, not compared with a key received separately")
    for warning in report.warnings:
        lines.append(f"Warning:    {warning}")
    if report.ok:
        lines.append("Result:     OK")
    else:
        lines.append(f"Result:     FAILED ({len(report.problems)} problem(s))")
        lines.extend(f"  - {problem}" for problem in report.problems)
    return lines


def _collection_lines(summary: dict[str, Any]) -> list[str]:
    """Devices, features, the run's marks and a merge's runs, as the manifest.json verify read gives them."""
    lines: list[str] = []
    devices = _mapping(summary.get("devices"))
    lines.append(
        f"Devices:    {summary.get('device_count', len(devices))}, "
        f"{summary.get('devices_connected', 0)} connected"
    )
    width = max((len(str(name)) for name in devices), default=0)
    for name, entry in sorted(devices.items(), key=lambda item: str(item[0])):
        entry = _mapping(entry)
        state = "connected" if entry.get("connected") else "not connected"
        platform = f", {entry.get('platform')}" if entry.get("platform") else ""
        lines.append(f"  {str(name).ljust(width)}  {entry.get('os') or 'os unknown'}{platform}, {state}")
    if summary.get("features_recorded") is False:
        lines.append("Features:   not recorded (collected before feature selection, which read everything)")
    else:
        collected = ", ".join(str(item) for item in _sequence(summary.get("features")))
        skipped = ", ".join(str(item) for item in _sequence(summary.get("features_skipped")))
        lines.append(f"Features:   collected: {collected or 'none'}")
        lines.append(f"            not collected: {skipped or 'none'}")
    run = _mapping(summary.get("run"))
    marks = []
    if run.get("interrupted"):
        reason = _mapping(run["interrupted"]).get("reason")
        marks.append(f"interrupted ({reason or 'cut short'})")
    if run.get("retry_of"):
        marks.append(f"a retry round of {run['retry_of']}")
    if run.get("merged_from") is not None:
        marks.append(f"a merge of {len(_sequence(run['merged_from']))} run(s)")
    if run.get("devices_not_requested"):
        marks.append(f"{len(_sequence(run['devices_not_requested']))} testbed device(s) not requested")
    if marks:
        lines.append(f"Run:        {'; '.join(marks)}")
    sources = summary.get("sources")
    if isinstance(sources, list):
        lines.append(f"Merged:     {len(sources)} run(s)" + ("" if sources else ", none of them recorded"))
        for source in sources:
            source = _mapping(source)
            versions = ", ".join(str(text) for text in _sequence(source.get("collector_versions"))) or "?"
            recorded = source.get("commands_sha256")
            lines.append(
                f"  {source.get('snapshot_id') or '?'}  {source.get('started_utc') or '?'} to "
                f"{source.get('finished_utc') or 'finish not recorded'}, by netstate {versions}, allowlist "
                + (f"sha256 {recorded}" if recorded else "hash not recorded")
            )
    return lines
