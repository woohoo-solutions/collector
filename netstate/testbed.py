"""The testbed file as text: what its device blocks say, read without pyATS.

pyATS hands over resolved values, and a value must never reach a manifest, so
what the engine needs from the file itself — which credential set a block
names, which devices `finalize` commented out and where they were — is read
from the text. The block shape is the one `disconet.testbedgen` writes and
edits; it imports the reader from here, so the two cannot drift apart.
"""

from __future__ import annotations

import re
from typing import Iterable


# Environment variable names, matching .env.example so a file written by the
# wizard and one written by hand read from the same place.
ENV_USERNAME = "DISCONET_USERNAME"
ENV_PASSWORD = "DISCONET_PASSWORD"
ENV_ENABLE = "DISCONET_ENABLE_PASSWORD"
ENV_JUMP_USERNAME = "DISCONET_JUMP_USERNAME"
ENV_JUMP_PASSWORD = "DISCONET_JUMP_PASSWORD"


def placeholder_name(address: str) -> str:
    """What a device is called before it has told us its hostname.

    Derived from the address so the name says which device it is, and so two
    unnamed devices cannot collide. `disconet finalize` replaces it with the
    hostname the device gave, once there is one.
    """
    return "dev_" + address.replace(".", "_").replace(":", "_")


# A device block opens with a name at exactly two spaces of indent, which is
# where `devices:` puts it. Anything deeper belongs to the device above. The
# name may define an anchor (`  R1: &xr`) for other devices to refer to: not
# read as a device, its lines joined the block above and were commented out
# with it. A device in any other form on its name line is caught by
# _check_blocks rather than read.
_DEVICE_LINE = re.compile(
    r"^  (?P<name>[A-Za-z0-9_.-]+):(?:[ \t]+(?P<anchor>&[^\s#]+))?\s*(?:#.*)?$"
)


_DEVICES_KEY = re.compile(r"^devices:\s*(?:#.*)?$")


# Any key at column 0: the end of the devices section.
_TOP_LEVEL_KEY = re.compile(r"^[A-Za-z_][\w.-]*\s*:")


# A device finalize itself commented out: the same name line, behind the
# prefix _comment_out adds. Recognised so that a later run with better
# evidence can bring the device back, rather than leaving it to be uncommented
# by hand: otherwise a device stays disabled for a reason that has since been
# found and fixed, and nothing in the file says so. A comment the name line
# carried live is carried behind the prefix too.
_DISABLED_LINE = re.compile(
    r"^  # (?P<name>[A-Za-z0-9_.-]+):(?:[ \t]+&[^\s#]+)?\s*(?:#.*)?$"
)


_DISABLED_MARKER = "  # --- NOT REACHED"
_DISABLED_BANNER = ("  # reason:", "  # Uncomment when it is fixed")


def _split_blocks(
    text: str,
) -> tuple[list[str], list[tuple[str, list[str], bool]], list[str]]:
    """The file as (preamble, [(name, lines, disabled), ...], trailer).

    Trailing blank and comment lines are pushed onto the following block rather
    than left on the previous one, so a comment written above a device travels
    with that device when the device is commented out.

    A block finalize disabled earlier is returned with ``disabled=True`` and
    its banner lines stripped, so the caller can revive it or leave it exactly
    as it was. Only lines in the shape _comment_out writes are part of it; a
    comment an engineer wrote after it travels with the next block instead,
    since reviving the device would uncomment it into a line YAML refuses.

    The trailer is everything from the first column-0 key after ``devices:``
    (a ``topology:`` section, say) to the end of the file, and any comment
    after a disabled last block. It is not a device and is re-emitted
    untouched.
    """
    lines = text.splitlines()
    preamble: list[str] = []
    blocks: list[tuple[str, list[str], bool]] = []
    trailer: list[str] = []
    index = 0
    while index < len(lines):
        preamble.append(lines[index])
        if _DEVICES_KEY.match(lines[index]):
            index += 1
            break
        index += 1
    else:
        return preamble, blocks, trailer

    body = lines[index:]
    for position, line in enumerate(body):
        if _TOP_LEVEL_KEY.match(line):
            trailer = body[position:]
            body = body[:position]
            break

    current: list[str] | None = None
    name = ""
    disabled = False
    pending: list[str] = []
    armed = False  # the NOT REACHED marker was seen; a disabled block follows
    pending_reason = ""
    # The disabled block's own lines above its name: the comments that were
    # written above the device when it was commented out with them.
    above: list[str] = []
    for line in body:
        if line.startswith(_DISABLED_MARKER):
            if current is not None:
                blocks.append((name, current, disabled))
                current = None
            # A marker with no device under it leaves its lines as comments
            # waiting for the next block, like any other.
            pending.extend(above)
            above = []
            armed = True
            continue
        if armed and line.startswith(_DISABLED_BANNER):
            if line.startswith("  # reason:"):
                pending_reason = line
            continue
        match = _DEVICE_LINE.match(line)
        if match:
            if current is not None:
                blocks.append((name, current, disabled))
            name = match.group("name")
            current = pending + above + [line]
            pending = []
            above = []
            disabled = False
            armed = False
            continue
        disabled_match = _DISABLED_LINE.match(line) if armed else None
        if disabled_match:
            if current is not None:
                blocks.append((name, current, disabled))
            name = disabled_match.group("name")
            # The reason travels with the block as its first line, so a block
            # left disabled is re-rendered with the reason it was disabled for.
            # Comments that were waiting for this device go in as _comment_out
            # would have written them, so reviving it gives them back as they
            # were; the blank lines before the banner were never kept.
            current = [pending_reason] if pending_reason else []
            current += [_commented(waiting) for waiting in pending if waiting.strip()]
            current += [kept if _is_commented(kept) else _commented(kept) for kept in above]
            current.append(line)
            pending_reason = ""
            pending = []
            above = []
            disabled = True
            armed = False
            continue
        if armed:
            above.append(line)
            continue
        if current is None:
            # Before the first device, the preamble; after a disabled block,
            # waiting for the next one.
            if blocks:
                pending.append(line)
            else:
                preamble.append(line)
            continue
        if disabled:
            # What _comment_out wrote under a disabled device belongs to it,
            # blank lines included. Anything else ends it, and waits for the
            # next block.
            if not line.strip() or _is_commented(line):
                current.append(line)
                continue
            blocks.append((name, current, disabled))
            current = None
            disabled = False
            pending.append(line)
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            pending.append(line)
            continue
        current.extend(pending)
        pending = []
        current.append(line)
    if current is not None:
        blocks.append((name, current, disabled))
    pending.extend(above)
    if pending:
        if trailer or (blocks and blocks[-1][2]):
            # Not into a disabled block, whose every line is uncommented
            # when it is revived.
            trailer = pending + trailer
        elif blocks:
            blocks[-1][1].extend(pending)
        else:
            preamble.extend(pending)
    return preamble, blocks, trailer


def _commented(line: str) -> str:
    """One line as _comment_out writes it."""
    if not line.strip():
        return ""
    return "  # " + line[2:] if line.startswith("  ") else "  # " + line


def _is_commented(line: str) -> bool:
    """Whether a line has the shape _comment_out gives a device's lines.

    A key or a comment under the device keeps its indent behind `  # `, and
    a comment written above it gains a `#`: `  #   os: iosxe`, `  # # note`.
    `  # --- Site B ---` is neither, so it is not a line that was commented
    out, and uncommenting it would write a line YAML refuses.
    """
    if line.strip() == "#":
        return True
    if not line.startswith("  # "):
        return False
    rest = line[4:]
    return rest[:1].isspace() or rest.startswith("#")


def _uncomment(lines: list[str]) -> list[str]:
    """Reverse of _comment_out: the block as it was before it was disabled."""
    out: list[str] = []
    for line in lines:
        if line.startswith("  # reason:"):
            continue
        if line.startswith("  # "):
            out.append("  " + line[4:])
        elif line.strip() == "#" or line.strip() == "":
            out.append("")
        else:
            out.append(line)
    # Trailing blank lines are the gap that separated it from the next block.
    while out and not out[-1].strip():
        out.pop()
    return out


# `%ENV{DISCONET_USERNAME}` is the testbed's own set, "1"; `_2` and on are the
# sets `disconet retry` wrote. Only the name is ever in the file, so only the
# name is ever read.
_CREDENTIAL_SET = re.compile(r"%ENV\{" + re.escape(ENV_USERNAME) + r"(?:_(?P<number>\d+))?\}")


def credential_set_of(lines: Iterable[str]) -> str:
    """The credential set a device block logs in with: "1", "2", ...

    A block with no `credentials:` of its own logs in with the testbed's, which
    is set 1. The number is what a run records against the device, so a later
    retry can count how many sets the device has been tried under without a
    value ever leaving the environment.
    """
    for line in lines:
        code = line.split("#", 1)[0]
        if "username" not in code:
            continue
        match = _CREDENTIAL_SET.search(code)
        if match:
            return match.group("number") or "1"
    return "1"


def credential_sets(text: str) -> dict[str, str]:
    """Every device block's credential set, live and commented out alike."""
    _preamble, blocks, _trailer = _split_blocks(text)
    return {
        name: credential_set_of(_uncomment(lines) if disabled else lines)
        for name, lines, disabled in blocks
    }


def block_address(lines: Iterable[str]) -> str:
    """The management address a device block connects to, or ""."""
    for line in lines:
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("ip:"):
            return stripped[3:].strip().strip("'\"")
    return ""


def disabled_devices(text: str) -> dict[str, str]:
    """Every device finalize commented out, by name, with the address it connects to.

    pyATS loads none of them, so whatever knows the testbed only through
    pyATS takes a disabled device for one the file has never named.
    """
    _preamble, blocks, _trailer = _split_blocks(text)
    return {
        name: block_address(_uncomment(lines))
        for name, lines, disabled in blocks
        if disabled
    }
