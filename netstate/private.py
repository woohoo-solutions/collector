"""Owner-only files and directories for everything a run writes about a network.

A snapshot, the estate database, a session transcript, a trace of the model's
requests: each describes a customer's network, and none is any business of
the machine's other accounts. Directories are made 0700 and files 0600,
whatever the umask; the command-line entry points also set the umask to 077
so that a writer this module does not know about (a pyATS subprocess, the
.docx and .xlsx writers) creates nothing more open than these do.

A directory found group- or world-accessible (an estate written before this
was fixed) is tightened to 0700 and said once in the log: owner decision of
11 November 2026, tighten and warn rather than refuse.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import TextIO

log = logging.getLogger(__name__)

DIR_MODE = 0o700
FILE_MODE = 0o600
UMASK = 0o077
# The files SQLite keeps beside a database in WAL or rollback mode.
SQLITE_SIBLINGS = ("-wal", "-shm", "-journal")


def owner_only_umask() -> int:
    """Set the process umask to 077; returns the one it replaces."""
    return os.umask(UMASK)


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - a filesystem without modes
        log.debug("could not chmod %s", path, exc_info=True)


def exposed(path: Path | str) -> bool:
    """Whether the group or others hold any permission on ``path``."""
    try:
        return bool(os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO))
    except OSError:
        return False


def tighten(path: Path | str, mode: int = DIR_MODE) -> bool:
    """Make an existing ``path`` owner-only, warning once when it was not. True when it changed."""
    path = Path(path)
    if not path.exists() or path.is_symlink() or not exposed(path):
        return False
    before = stat.S_IMODE(path.stat().st_mode)
    _chmod(path, mode)
    log.warning(
        "%s was readable by other accounts on this machine (mode %o); it is now %o. "
        "Files written into it by an earlier run keep their modes: chmod -R go= %s",
        path, before, mode, path,
    )
    return True


def make_dir(path: Path | str) -> Path:
    """``mkdir -p`` with every directory it creates 0700.

    A directory already there is left as it is: it may be the operator's
    own (the working directory, an output folder), and only the estate and
    snapshot roots, through `tighten`, are this tool's to correct.
    """
    path = Path(path)
    missing = []
    probe = path
    while not probe.exists() and probe != probe.parent:
        missing.append(probe)
        probe = probe.parent
    path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    # mkdir's mode is cut by the umask and `parents` ignores it for the
    # intermediate directories, so each one made here is set explicitly.
    for made in missing:
        _chmod(made, DIR_MODE)
    return path


def make_child_dir(path: Path | str) -> Path:
    """Create exactly ``path`` (not its parents) 0700; FileExistsError when it is there."""
    path = Path(path)
    path.mkdir(mode=DIR_MODE)
    _chmod(path, DIR_MODE)
    return path


def open_text(path: Path | str) -> TextIO:
    """``path`` opened for writing text as a 0600 file, truncated; its parent made 0700 if missing."""
    path = Path(path)
    make_dir(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        os.fchmod(descriptor, FILE_MODE)
    except OSError:  # pragma: no cover - a filesystem without modes
        pass
    return os.fdopen(descriptor, "w", encoding="utf-8")


def write_text(path: Path | str, text: str) -> None:
    """Write ``text`` to ``path`` as a 0600 file, its parent made 0700 if missing."""
    with open_text(path) as handle:
        handle.write(text)


def secure_file(path: Path | str) -> None:
    """Set an existing file 0600."""
    if Path(path).exists():
        _chmod(Path(path), FILE_MODE)


def secure_sqlite(path: Path | str) -> None:
    """The database and the files SQLite keeps beside it, 0600.

    SQLite creates its -wal and -shm files with the database file's own
    mode, so a database made 0600 before its first write keeps them so.
    """
    path = Path(path)
    for candidate in (path, *(path.with_name(path.name + suffix) for suffix in SQLITE_SIBLINGS)):
        secure_file(candidate)
