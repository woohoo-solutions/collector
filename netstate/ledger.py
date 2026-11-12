"""Which configuration lines a reader consumed, by line number.

The statement-level coverage figure (`disconet.statements`) needs to know,
for each line of a device's running configuration, whether some reader of
this tool extracted its meaning. That is a fact about the readers, so the
readers state it: each registers the lines it matched through `consume`,
and the counter reads the ledger back. Nothing is inferred from a stanza
heading, which is how the stanza-level figure came to credit every line
under `interface` as read.

Line numbers ride on the configuration text itself so that the ~30 places
that split a configuration need not change shape: `ConfigLine` is a `str`
that also knows its 1-based line number, and `ConfigPath` is a `list` of
ancestry texts that also knows the line number of each element. A reader
that kept the object it matched can hand it to `consume` as it is; a reader
that called `.strip()` on it has a plain `str` and must keep the original.

The ledger records only while the counter is running the readers for one
device (`recording`). Outside that, `consume` does nothing, so a document
build that calls the same readers pays nothing and changes nothing. This
module must not import anything from DiscoNet: every reader imports it.
"""

from __future__ import annotations

import contextlib
import contextvars
from dataclasses import dataclass, field
from typing import Iterable, Iterator

BUCKETS = ("parsed", "modelled", "ignored")


class ConfigLine(str):
    """One line of a configuration, as text, carrying its 1-based line number."""

    __slots__ = ("line_no",)

    def __new__(cls, text: str, line_no: int = 0) -> "ConfigLine":
        made = super().__new__(cls, text)
        made.line_no = line_no
        return made

    def __reduce__(self):
        return (ConfigLine, (str(self), self.line_no))


class ConfigPath(list):
    """A statement with its ancestry, outermost first, as `list[str]`.

    `line_nos` holds the line number of each element, so `line_nos[-1]` is
    the statement's own line and the others are the lines that opened the
    blocks it sits in. A slice or a copy is a plain list and loses them.
    """

    __slots__ = ("line_nos",)

    def __init__(self, texts: Iterable[str] = (), line_nos: Iterable[int] = ()):
        super().__init__(texts)
        self.line_nos = tuple(line_nos)

    def __reduce__(self):
        return (ConfigPath, (list(self), self.line_nos))

    @property
    def line_no(self) -> int:
        return self.line_nos[-1] if self.line_nos else 0


def numbered_lines(config: str) -> list[ConfigLine]:
    """`config.splitlines()`, each line carrying its line number.

    For the readers that walk the configuration line by line themselves.
    """
    return [ConfigLine(text, number) for number, text in enumerate(config.splitlines(), 1)]


def line_numbers_of(items: Iterable[object]) -> set[int]:
    """Every line number the given lines, paths, stanzas or ints carry.

    A `ConfigPath` gives its ancestors too: a reader that read `address
    10.0.0.1` under `ntp` / `server` read which server it was from the lines
    above it. A stanza (a list of `ConfigLine`) gives every line in it, so
    pass a stanza only where the reader read all of it. Plain strings carry
    nothing and are skipped.
    """
    found: set[int] = set()
    for item in items:
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            found.add(item)
        elif isinstance(item, ConfigLine):
            found.add(item.line_no)
        elif isinstance(item, ConfigPath):
            found.update(n for n in item.line_nos if n)
        elif isinstance(item, (list, tuple)):
            found |= line_numbers_of(item)
    return found


@dataclass
class StatementLedger:
    """What each reader consumed, per device: `{device: {line_no: (bucket, reader_key)}}`.

    One per snapshot. The first reader to claim a line keeps it, so the
    figure does not depend on two readers agreeing; `parsed` outranks the
    other buckets whoever came first.
    """

    lines: dict[str, dict[int, tuple[str, str]]] = field(default_factory=dict)

    def consume(self, device: str, line_nos: Iterable[object], reader_key: str, bucket: str = "parsed") -> None:
        if bucket not in BUCKETS:
            raise ValueError(f"unknown bucket {bucket!r}")
        held = self.lines.setdefault(device, {})
        for number in line_numbers_of(line_nos):
            current = held.get(number)
            if current is None or (bucket == "parsed" and current[0] != "parsed"):
                held[number] = (bucket, reader_key)

    def for_device(self, device: str) -> dict[int, tuple[str, str]]:
        return self.lines.get(device, {})


@dataclass
class _Recording:
    ledger: StatementLedger
    device: str


_CURRENT: contextvars.ContextVar[_Recording | None] = contextvars.ContextVar("statement_ledger", default=None)


@contextlib.contextmanager
def recording(ledger: StatementLedger, device: str) -> Iterator[StatementLedger]:
    """Record every `consume` made while the readers run for `device`."""
    token = _CURRENT.set(_Recording(ledger, device))
    try:
        yield ledger
    finally:
        _CURRENT.reset(token)


def consume(device: str | None, line_nos: Iterable[object], reader_key: str, bucket: str = "parsed") -> None:
    """Register the configuration lines a reader extracted the meaning of.

    `device` is the device the reader was given, or None for a reader that
    is handed only the configuration text; either way the lines go to the
    device being recorded. A call for another device, or with no recording
    running, does nothing: a reader must never depend on this.
    """
    current = _CURRENT.get()
    if current is None or (device is not None and device != current.device):
        return
    current.ledger.consume(current.device, line_nos, reader_key, bucket)
