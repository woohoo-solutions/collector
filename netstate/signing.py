"""Ed25519 signatures for a snapshot export, opt-in with `export --sign`.

The hashes in an export manifest prove that an archive is the one its
manifest describes. They say nothing about who made it: anyone who changes a
file can recompute its hash and write the new one in. A signature over the
export manifest adds that. The prospect signs with a key kept on their own
machine and gives the owner the public half by a second channel (a phone
call, a text message, a separate email), so that whoever intercepts the
archive cannot also replace the key it is checked against.

Written for netstate, which is Apache-2.0, and written fresh: netlicense
signs licences the same way but is proprietary, and nothing of it is
imported or copied here. Only its public-key text form is shared,
``ed25519 <kid> <base64 of the raw 32-byte key>`` with the kid the first 16
hex characters of the key's SHA-256, so that a key line read out over the
phone means the same thing to both.

``cryptography`` is imported inside the functions that need it, never at
module level. An unsigned archive is exported and verified without it, and a
Python that lacks it is told what to install rather than failing on import.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALG = "ed25519"

# As netlicense prints it, so a kid read from either names the same key.
KID_LENGTH = 16
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64

# One key per user, reused for every export: the owner learns it once, by
# the second channel, and every later archive from the same prospect is
# checked against the same line.
KEY_DIRECTORY = (".config", "disconet")
KEY_FILE_NAME = "export_ed25519.pem"

LINE_FORM = "'ed25519 <kid> <base64>'"


class SigningError(RuntimeError):
    """A key or signature that cannot be used, or no `cryptography` to use one with."""


def default_key_path() -> Path:
    """Where `export --sign` keeps its private key unless --key says otherwise.

    Read from the home directory each time rather than fixed at import, so a
    test (or a shell) that points HOME elsewhere gets its own key there.
    """
    return Path.home().joinpath(*KEY_DIRECTORY, KEY_FILE_NAME)


def _cryptography():
    """The three pieces of `cryptography` this module uses, or a SigningError saying how to get them."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise SigningError(
            "signing needs the Python package 'cryptography', which is not installed in this "
            "Python. Install it where DiscoNet is installed (`pip install cryptography`). An "
            "archive that is not signed is exported and verified without it."
        ) from exc
    return ed25519, serialization, InvalidSignature


def key_id(public: bytes) -> str:
    """The short name of a public key: the first 16 hex characters of its SHA-256."""
    return hashlib.sha256(public).hexdigest()[:KID_LENGTH]


def key_line(public: bytes) -> str:
    """The public key as one line of text, the form that is read out and pasted."""
    return f"{ALG} {key_id(public)} {base64.b64encode(public).decode('ascii')}"


def _strict_b64(text: str, length: int, what: str) -> bytes:
    """Base64 that decodes to exactly ``length`` bytes and re-encodes to itself.

    Strict, so that two spellings of one key (padding dropped, a stray
    character the lenient decoder skips) cannot both pass for the line the
    owner was given.
    """
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise SigningError(f"{what} is not base64: {exc}") from exc
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != text:
        raise SigningError(f"{what} is not {length} bytes of canonical base64")
    return raw


def parse_key_line(text: str) -> bytes:
    """The raw 32-byte public key a key line names; SigningError for anything else.

    The kid is checked against the key: a line whose kid was edited, or
    whose key was, would otherwise name one key and hold another, and the
    kid is what a person compares by eye.
    """
    parts = str(text).strip().split()
    if len(parts) != 3 or parts[0] != ALG:
        raise SigningError(f"a public key is one line of the form {LINE_FORM}; got {str(text).strip()[:80]!r}")
    public = _strict_b64(parts[2], PUBLIC_KEY_BYTES, "the public key")
    if key_id(public) != parts[1]:
        raise SigningError(
            f"the key line names key id {parts[1]}, but the key in it has id {key_id(public)}: "
            f"the line was altered"
        )
    return public


def read_public_key(value: str | Path) -> bytes:
    """A public key given as a key line, or as the path of a file that holds one.

    A file may carry blank lines and ``#`` comments around its one key line,
    so the line can be saved with a note of who sent it and when. More than
    one key line is refused rather than guessed between.
    """
    text = str(value).strip()
    if text.startswith(f"{ALG} "):
        return parse_key_line(text)
    path = Path(text).expanduser()
    if not path.is_file():
        raise SigningError(
            f"{text[:80]!r} is neither a key line of the form {LINE_FORM} nor a file holding one"
        )
    try:
        lines = [
            line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except (OSError, UnicodeDecodeError) as exc:
        raise SigningError(f"could not read the public key file {path}: {exc}") from exc
    if len(lines) != 1:
        raise SigningError(
            f"{path} holds {len(lines)} key lines; it should hold the one line the sender gave you"
        )
    return parse_key_line(lines[0])


@dataclass(frozen=True)
class SigningKey:
    """The private key an export is signed with, and where it came from."""

    path: Path
    created: bool
    public: bytes
    _private: Any

    @property
    def line(self) -> str:
        return key_line(self.public)

    @property
    def kid(self) -> str:
        return key_id(self.public)

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)


def _public_bytes(private: Any) -> bytes:
    _ed25519, serialization, _invalid = _cryptography()
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )


def _guarded(path: Path, descriptor: int) -> None:
    """Refuse a key file that someone other than its user can read or write, or that is not theirs, as ssh does.

    The key is created 0600 in a 0700 folder, but one restored from a backup
    or copied in by hand can be 0644 in a ~/.config/disconet that is 0755,
    and on a shared machine anyone could then sign archives that verify as
    this prospect's. Checked on the open file (fstat), so that what is
    checked is what is read. POSIX only: Windows has no such mode bits, and
    a Python without os.geteuid has no owner to compare with.
    """
    if os.name != "posix" or not hasattr(os, "geteuid"):
        return
    status = os.fstat(descriptor)
    if status.st_uid != os.geteuid():
        raise SigningError(
            f"the signing key {path} belongs to another user (uid {status.st_uid}): a private key must be "
            f"yours alone. Use your own key, or take ownership of this one and run 'chmod 600 {path}'"
        )
    if status.st_mode & 0o077:
        raise SigningError(
            f"the signing key {path} can be read or written by others (mode {stat.S_IMODE(status.st_mode):04o}): "
            f"a private key must be readable by you alone. Run 'chmod 600 {path}', then export again"
        )


def _load_private(path: Path) -> Any:
    ed25519, serialization, _invalid = _cryptography()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise SigningError(f"could not read the signing key {path}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "rb") as handle:
            _guarded(path, handle.fileno())
            data = handle.read()
    except OSError as exc:
        raise SigningError(f"could not read the signing key {path}: {exc}") from exc
    try:
        private = serialization.load_pem_private_key(data, password=None)
    except TypeError as exc:
        # The key is created unencrypted, guarded by its file mode as an ssh
        # key is; one with a passphrase was put there by hand.
        raise SigningError(
            f"the signing key {path} is encrypted with a passphrase; DiscoNet's export key "
            f"is an unencrypted PKCS8 PEM kept readable by you alone. Pass --key with "
            f"another path to have a new one created there"
        ) from exc
    except ValueError as exc:
        raise SigningError(f"{path} is not a PEM private key: {exc}") from exc
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise SigningError(f"{path} holds a {type(private).__name__}, not an Ed25519 key")
    return private


def _create_private(path: Path) -> Any | None:
    """Write a new key at ``path``, 0600 in a 0700 directory; None when one appeared there first.

    O_EXCL, so that two exports started at once cannot each write a key and
    leave the owner holding the line of the one that was overwritten; the
    loser reads the winner's key instead.
    """
    ed25519, serialization, _invalid = _cryptography()
    directory = path.parent
    if not directory.is_dir():
        try:
            directory.mkdir(mode=0o700, parents=True)
            # mkdir's mode passes through the umask; the key's directory is
            # the owner's alone whatever the umask says.
            os.chmod(directory, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SigningError(f"could not create {directory} for the signing key: {exc}") from exc
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return None
    except OSError as exc:
        raise SigningError(f"could not create the signing key {path}: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        # Half a key is no key: removed, so the next export creates a whole one.
        try:
            os.unlink(path)
        except OSError:
            pass
        raise SigningError(f"could not write the signing key {path}: {exc}") from exc
    return private


def load_or_create(path: Path | str | None = None) -> SigningKey:
    """The signing key at ``path`` (default: :func:`default_key_path`), created on first use."""
    path = Path(path).expanduser() if path is not None else default_key_path()
    if path.exists() and not path.is_file():
        raise SigningError(f"{path} is not a file; pass --key with the path of a key file")
    created = False
    if path.is_file():
        private = _load_private(path)
    else:
        private = _create_private(path)
        created = private is not None
        if private is None:
            private = _load_private(path)
    return SigningKey(path=path, created=created, public=_public_bytes(private), _private=private)


def signature_document(key: SigningKey, message: bytes) -> bytes:
    """``export-manifest.sig``: the algorithm, the key line and the signature over ``message``.

    The key travels inside the archive so that a receiver with no key yet
    can still check that the archive is whole, and is told plainly that
    this proves nothing about the sender until the key is compared with one
    received apart from it.
    """
    document = {
        "alg": ALG,
        "public_key": key.line,
        "signature": base64.b64encode(key.sign(message)).decode("ascii"),
    }
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")


@dataclass(frozen=True)
class Signature:
    """What an ``export-manifest.sig`` says: the signing key and the signature."""

    public: bytes
    signature: bytes

    @property
    def line(self) -> str:
        return key_line(self.public)

    @property
    def kid(self) -> str:
        return key_id(self.public)


def read_signature(data: bytes) -> Signature:
    """Parse an ``export-manifest.sig``; SigningError for one that is not of the form written above."""
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SigningError(f"the signature file is not JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SigningError("the signature file is not a JSON object")
    if document.get("alg") != ALG:
        raise SigningError(f"the signature's algorithm is {document.get('alg')!r}, not {ALG!r}")
    public = parse_key_line(str(document.get("public_key") or ""))
    signature = _strict_b64(str(document.get("signature") or ""), SIGNATURE_BYTES, "the signature")
    return Signature(public=public, signature=signature)


def verify(public: bytes, signature: bytes, message: bytes) -> bool:
    """Is ``signature`` the signature of ``message`` by ``public``? SigningError without `cryptography`."""
    ed25519, _serialization, InvalidSignature = _cryptography()
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
