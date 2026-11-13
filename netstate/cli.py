"""The Collector's command line: collect, export and verify.

    disconet-collector collect --testbed testbed.yaml
    disconet-collector export --snapshot snapshots/<id>
    disconet-collector verify <file>.export.tar.gz

`python -m netstate` is the same command.

Plain text on stdout, no prompt unless a device offers a host key that is not
pinned and a person is at the terminal. Exit codes are the same for every
command: 0 when everything held, 1 when the work was done in part (some
devices did not answer, an archive did not verify), 2 when nothing could be
done (no testbed, an allowlist that will not load, a file that is no archive).

This module imports nothing beyond netstate and the standard library at load
time. `verify` never loads pyATS, so the recipient of an archive can check it
on a machine with no pyATS installed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from netstate import __version__

DEFAULT_BASE_DIR = "snapshots"
STATUSES = ("parsed", "empty", "unparsed", "raw", "failed")
PYATS_MODULES = {"pyats", "genie", "unicon"}


def _out(text: str = "", stream: TextIO | None = None) -> None:
    print(text, file=stream or sys.stdout)


def _feature_list(value: str) -> list[str]:
    from netstate.collector import ALL_FEATURES

    text = value.strip().lower()
    if text == "all":
        return list(ALL_FEATURES)
    if text == "none":
        return []
    keys = [part.strip() for part in text.split(",") if part.strip()]
    unknown = [key for key in keys if key not in ALL_FEATURES]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown feature(s) {', '.join(unknown)}. "
            f"Choose from {', '.join(ALL_FEATURES)}, or 'all' or 'none'."
        )
    return keys


def _cidr(value: str) -> list[str]:
    parts = [part.strip() for part in value.split(",") if part.strip()]
    for part in parts:
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"not a subnet: {part}") from exc
    return parts


def _device_list(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    from netstate.collector import (
        ALL_FEATURES,
        DEFAULT_COMMAND_TIMEOUT,
        DEFAULT_COMMANDS_FILE,
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_CRAWL_DEPTH,
        DEFAULT_CRAWL_LIMIT,
        DEFAULT_DISCOVERY_MODE,
        DEFAULT_PROBE_LIMIT,
        DEFAULT_WORKERS,
        DISCOVERY_MODES,
    )

    parser = argparse.ArgumentParser(
        prog="disconet-collector",
        description="Read-only collection of network device state: collect, export, verify.",
    )
    parser.add_argument("--version", action="version", version=f"disconet-collector {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser(
        "collect",
        help="log in to the testbed's devices, send only allowlisted show commands, store a redacted snapshot",
        description=(
            "Log in to every device in a pyATS testbed over SSH, send only the commands "
            "in the allowlist, and store the answers, redacted, in a snapshot directory."
        ),
    )
    collect.add_argument("--testbed", required=True, metavar="PATH", help="pyATS testbed YAML")
    collect.add_argument("--devices", type=_device_list, metavar="A,B",
                         help="comma-separated subset of testbed devices (default: all)")
    collect.add_argument("--features", type=_feature_list, metavar="LIST",
                         help=f"optional groups to collect, comma-separated ({', '.join(ALL_FEATURES)}), "
                              f"or 'all' or 'none' (default: all the allowlist offers)")
    collect.add_argument("--mode", choices=list(DISCOVERY_MODES), default=DEFAULT_DISCOVERY_MODE,
                         help=f"how much a link must prove before it counts (default: {DEFAULT_DISCOVERY_MODE}); "
                              f"the commands sent are the same either way")
    collect.add_argument("--base-dir", default=DEFAULT_BASE_DIR, metavar="DIR",
                         help=f"where snapshot directories are written (default: {DEFAULT_BASE_DIR})")
    collect.add_argument("--commands", default=str(DEFAULT_COMMANDS_FILE), metavar="PATH",
                         help="show-command allowlist (default: the commands.yaml installed with netstate)")
    collect.add_argument("--connect-timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT, metavar="SEC",
                         help=f"seconds to establish a session (default: {DEFAULT_CONNECT_TIMEOUT})")
    collect.add_argument("--command-timeout", type=int, default=DEFAULT_COMMAND_TIMEOUT, metavar="SEC",
                         help=f"seconds for one command (default: {DEFAULT_COMMAND_TIMEOUT})")
    collect.add_argument("--workers", type=int, default=DEFAULT_WORKERS, metavar="N",
                         help=f"devices collected in parallel (default: {DEFAULT_WORKERS})")
    collect.add_argument("--session-log", action="store_true",
                         help="write the SSH dialog to session.log in the snapshot, credentials replaced")
    collect.add_argument("--double-enable", action="store_true",
                         help="send 'enable' a second time after login on every device")
    collect.add_argument("--allow-legacy-ssh", action="store_true",
                         help="when a device's ssh refuses to negotiate, retry with the legacy algorithms "
                              "it offers (SHA-1 key exchange, ssh-rsa, CBC). Off by default")
    collect.add_argument("--allow-telnet", action="store_true",
                         help="where ssh cannot work and TCP/23 answers, log in over telnet, which sends "
                              "the login in clear. Off by default")
    collect.add_argument("--verify-reachability", action="store_true",
                         help="also ping the neighbour addresses each device learned; the only thing "
                              "sent that is not a show command, so off by default")
    collect.add_argument("--probe-limit", type=int, default=DEFAULT_PROBE_LIMIT, metavar="N",
                         help=f"maximum probes per device (default: {DEFAULT_PROBE_LIMIT})")
    collect.add_argument("--crawl", action="store_true",
                         help="also log in to switches the devices name over CDP/LLDP, inside --crawl-scope")
    collect.add_argument("--crawl-scope", type=_cidr, action="append", metavar="CIDR",
                         help="subnet the crawl may enter (repeatable, or comma-separated); "
                              "without one the crawl enters nothing")
    collect.add_argument("--crawl-depth", type=int, default=DEFAULT_CRAWL_DEPTH, metavar="N",
                         help=f"hops below the listed devices (default: {DEFAULT_CRAWL_DEPTH})")
    collect.add_argument("--crawl-limit", type=int, default=DEFAULT_CRAWL_LIMIT, metavar="N",
                         help=f"devices the crawl may visit in all (default: {DEFAULT_CRAWL_LIMIT})")
    collect.add_argument("-v", "--verbose", action="store_true", help="log the sessions to the terminal")
    collect.set_defaults(func=cmd_collect)

    export = sub.add_parser(
        "export",
        help="pack a snapshot into one archive: the collection, and the testbed without its secrets",
        description=(
            "Write one gzip-compressed tar file holding the collection and nothing else: the "
            "manifest, every raw and parsed file it names, the testbed with every credential "
            "replaced, and an export manifest with the SHA-256 of each file. Logs, .env, "
            "known_hosts and the estate database are never included."
        ),
    )
    export.add_argument("--snapshot", metavar="DIR",
                        help="snapshot directory (default: the newest under --base-dir)")
    export.add_argument("--base-dir", default=DEFAULT_BASE_DIR, metavar="DIR",
                        help=f"where to look for the newest snapshot (default: {DEFAULT_BASE_DIR})")
    export.add_argument("--testbed", default=None, metavar="PATH",
                        help="the testbed the run used (default: the one the manifest names)")
    export.add_argument("--output", default=None, metavar="FILE",
                        help="where to write the archive (default: beside the snapshot directory)")
    export.add_argument("--sign", action="store_true",
                        help="sign the export manifest with your Ed25519 key, created on first use")
    export.add_argument("--key", default=None, metavar="PATH",
                        help="the private key to sign with (implies --sign)")
    export.set_defaults(func=cmd_export)

    verify = sub.add_parser(
        "verify",
        help="check an export archive: every hash, the summary, the allowlist and any signature",
        description=(
            "Check an archive written by `disconet-collector export` in place, without unpacking it. "
            "Needs no device and no pyATS. Exit 0 when every check holds, 1 when any does "
            "not, 2 when the file is missing or is not a gzip-compressed tar."
        ),
    )
    verify.add_argument("archive", metavar="ARCHIVE", help="the .export.tar.gz file to check")
    verify.add_argument("--public-key", default=None, metavar="KEY",
                        help="the sender's public key line ('ed25519 <kid> <base64>'), or a file holding it")
    verify.add_argument("--allowlist", default=None, metavar="PATH",
                        help="the allowlist to compare with (default: the one installed with netstate)")
    verify.set_defaults(func=cmd_verify)
    return parser


# --- collect -----------------------------------------------------------------


def _confirm_host_key(target: Any, keys: Sequence[Any]) -> bool:
    """The first-use prompt: show the fingerprints, pin only on an explicit yes."""
    _out()
    _out(f"  {target.device} ({target.pattern}) offers a host key that is not pinned:")
    for key in keys:
        _out(f"    {key.key_type:<22} {key.fingerprint}")
    _out("  Compare it with the device's own (for example `show crypto key mypubkey rsa`, "
         "`show ssh server` or `show system ssh`) or your records.")
    try:
        answer = input("  Trust and pin it? (y/N) ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def device_note(device: dict) -> str:
    """What a collected device's row must still say: how the login was made, and a testbed that is wrong."""
    notes = []
    if device.get("declared_os"):
        notes.append(f"the testbed declares os: {device['declared_os']}; the device proved to run "
                     f"{device.get('os')} and was collected as that")
    if device.get("ssh_options"):
        notes.append(f"logged in only after adding legacy SSH algorithms ({device['ssh_options']})")
    if device.get("protocol"):
        notes.append(f"logged in over {device['protocol']} after the ssh client refused this device; "
                     f"the testbed still says ssh")
    note = "; ".join(notes) + ". Correct the testbed" if notes else ""
    if device.get("ssh_client"):
        # Said whenever it happened: the next run falls back the same way by
        # itself, and a key this short is weak cryptography to fix on the device.
        bits = device.get("host_key_bits")
        size = f" of {bits} bits" if bits else ""
        said = f"logged in through {device['ssh_client']}: OpenSSH refuses this device's RSA host key{size}"
        note = f"{note}; {said}" if note else said
    return note


def collect_table(manifest: dict) -> list[str]:
    """One line per device: OS, connected, the count of each command status, and the error."""
    rows = [("Device", "OS", "Connected", *(s.capitalize() for s in STATUSES), "Note")]
    for name, device in sorted(manifest["devices"].items()):
        counts: dict[str, int] = {}
        for command in device["commands"]:
            # Probes are counted on their own line, as the summary counts them.
            if str(command.get("command", "")).startswith("ping "):
                continue
            counts[command["status"]] = counts.get(command["status"], 0) + 1
        rows.append((
            name, device.get("os") or "-", "yes" if device["connected"] else "no",
            *(str(counts[s]) if counts.get(s) else "-" for s in STATUSES),
            device.get("error") or device_note(device),
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]) - 1)]
    return ["  " + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row[:-1])) + "  " + row[-1]
            for row in rows]


def cmd_collect(args: argparse.Namespace) -> int:
    from netstate.collector import CollectionError, CommandNotAllowed, CommandPolicy, feature_label, run_collect

    try:
        policy = CommandPolicy.load(args.commands)
    # A malformed file (the engine turns its YAML error into a CollectionError)
    # or an entry that is not a show command is refused here, before any
    # device is contacted.
    except (CommandNotAllowed, CollectionError, OSError) as exc:
        _out(f"Refused: the allowlist did not load: {exc}")
        return 2
    features = list(policy.available_features) if args.features is None else \
        [key for key in args.features if key in policy.available_features]
    crawl_scope = [part for group in (args.crawl_scope or []) for part in group]
    _out(f"Collecting: {', '.join(feature_label(key) for key in features) or 'base state only'}")
    _out(f"Mode:       {args.mode}")
    if args.crawl:
        _out(f"Crawl:      up to {args.crawl_limit} switch(es), {args.crawl_depth} hop(s), "
             f"inside {', '.join(crawl_scope) or 'no subnet (nothing will be entered)'}")
    try:
        manifest = run_collect(
            testbed_path=args.testbed,
            base_dir=args.base_dir,
            devices=args.devices,
            commands_file=args.commands,
            log_stdout=args.verbose,
            connect_timeout=args.connect_timeout,
            command_timeout=args.command_timeout,
            workers=args.workers,
            verify_reachability=args.verify_reachability,
            probe_limit=args.probe_limit,
            features=features,
            session_log=args.session_log,
            mode=args.mode,
            double_enable=args.double_enable,
            crawl=args.crawl,
            crawl_depth=args.crawl_depth,
            crawl_limit=args.crawl_limit,
            crawl_scope=crawl_scope,
            allow_legacy_ssh=args.allow_legacy_ssh,
            allow_telnet=args.allow_telnet,
            confirm_host_key=_confirm_host_key if sys.stdin.isatty() else None,
        )
    except CommandNotAllowed as exc:
        _out(f"Refused: {exc}")
        return 2
    except CollectionError as exc:
        _out(f"Collection failed: {exc}")
        return 2

    summary = manifest["summary"]
    root = Path(args.base_dir) / manifest["snapshot_id"]
    _out()
    _out(f"Snapshot {manifest['snapshot_id']}")
    for line in collect_table(manifest):
        _out(line)
    _out()
    _out(f"  Snapshot: {root}")
    _out(f"  Log:      {root / 'collect.log'}")
    if args.session_log:
        _out(f"  Session:  {root / 'session.log'} (SSH dialog, credentials removed)")
    if summary.get("redacted_lines"):
        _out(f"  Redacted: {summary['redacted_lines']} line(s) carrying credential material")
    if summary.get("probes_sent"):
        failed = summary.get("probes_failed")
        _out(f"  Probes:   {summary['probes_sent']} ping(s) to learned neighbours"
             + (f", {failed} could not complete" if failed else ""))
    crawl = manifest.get("crawl") or {}
    if crawl.get("enabled"):
        _out(f"  Crawl:    {len(crawl.get('visited') or [])} device(s) visited, "
             f"{len(crawl.get('refused') or [])} declined")
    for device in sorted(manifest["devices"].values(), key=lambda entry: entry["name"]):
        if not device["connected"] and device.get("connect_log"):
            _out(f"  {device['name']}: SSH dialog in {root / device['connect_log']} (redacted)")
    _out()
    if summary["devices_connected"] == 0:
        _out("No device was reachable; nothing was collected.")
        return 1
    unreachable = summary["devices_total"] - summary["devices_connected"]
    if unreachable or summary["commands_failed"]:
        _out(f"Incomplete: {unreachable} device(s) unreachable, {summary['commands_failed']} "
             f"command(s) failed. The snapshot is usable but partial.")
        return 1
    return 0


# --- export ------------------------------------------------------------------


def _newest_snapshot(base_dir: Path | str) -> Path | None:
    """The run with the latest created_at in its manifest; the name breaks a tie."""
    from netstate import store

    runs = []
    for path in store.iter_snapshot_dirs(base_dir):
        try:
            created = str(json.loads((path / "manifest.json").read_text(encoding="utf-8")).get("created_at") or "")
        except (OSError, ValueError, AttributeError):
            continue
        runs.append((created, path.name, path))
    return max(runs)[2] if runs else None


def cmd_export(args: argparse.Namespace) -> int:
    from netstate import export as exports
    from netstate.collector import CollectionError

    if not args.snapshot:
        newest = _newest_snapshot(args.base_dir)
        if newest is None:
            _out(f"No snapshot given and nothing under {args.base_dir} looks like one. "
                 f"Pass --snapshot, or collect first.")
            return 2
        args.snapshot = str(newest)
        _out(f"  Snapshot: {newest}, the newest run there")
    _out()
    _out(f"Exporting {args.snapshot}")
    try:
        result = exports.export_snapshot(
            args.snapshot, testbed=args.testbed, output=args.output,
            sign=args.sign or bool(args.key), key_path=args.key,
        )
    # OSError too: the backstop for an I/O failure the engine did not turn
    # into a refusal, so the operator reads a refusal and exit 2, not a traceback.
    except (CollectionError, OSError) as exc:
        _out(f"Export refused: {exc}")
        _out("  Nothing was written.")
        return 2

    _out(f"  Archive:  {result.path}")
    _out(f"  Size:     {exports.human_size(result.size)} ({result.size:,} bytes)")
    _out(f"  SHA-256:  {result.sha256}")
    _out(f"  Files:    {result.member_count} (the manifest, {result.collected_files} collected file(s), "
         f"the testbed and the export manifest" + (", and its signature)" if result.signed else ")"))
    _out(f"  Testbed:  {result.testbed_source}, {result.redacted_values} credential value(s) replaced; "
         f"%ENV and %ASK references and usernames kept, comments dropped")
    if result.left_out:
        _out(f"  Left out: {len(result.left_out)} file(s) in raw/ or state/ that the manifest does not name:")
        for name in result.left_out[:10]:
            _out(f"            {name}")
        if len(result.left_out) > 10:
            _out(f"            and {len(result.left_out) - 10} more")
    if result.synthetic:
        _out(f"  Demo:     {result.synthetic_notice or 'the synthetic demonstration estate'}")
    for warning in result.warnings:
        _out(f"  Note:     {warning}")
    if result.signed:
        made = "created now, " if result.key_created else ""
        _out(f"  Signed:   with {result.key_path} ({made}kept for every export)")
        _out(f"  Public key: {result.public_key_line or ''}")
        _out(f"            {exports.SECOND_CHANNEL}")
    _out()
    _out(f"  Before sending: the archive carries each device's raw/ text as collected, already "
         f"redacted; read it in the snapshot if you have not. `disconet-collector verify {result.path}` "
         f"shows what the recipient will check")
    _out(f"  Next: {exports.NEXT_STEP}, e.g.")
    _out(f"        age -r <their age public key> -o {result.path}.age {result.path}")
    _out()
    return 0


# --- verify ------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    from netstate import export as exports

    report = exports.verify_archive(args.archive, public_key=args.public_key, allowlist=args.allowlist)
    _out()
    # The archive is someone else's, and the summary is built from what it
    # says; a summary that cannot be printed has not been shown to hold.
    try:
        lines = list(exports.summary_lines(report))
    except Exception as exc:  # noqa: BLE001 - any failure, said as a result
        for problem in report.problems:
            _out(f"  {problem}")
        _out(f"Result: FAILED (the summary could not be printed: {type(exc).__name__})")
        _out()
        return 2 if not report.readable else 1
    for line in lines:
        _out(line)
    _out()
    if not report.readable:
        return 2
    return 0 if report.ok else 1


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main(argv: Sequence[str] | None = None) -> int:
    # Everything a run writes, and every process it starts (pyATS), is
    # readable by its owner only: a snapshot describes a customer's network.
    from netstate.private import owner_only_umask

    owner_only_umask()
    args = build_parser().parse_args(argv)
    _setup_logging(getattr(args, "verbose", False))
    try:
        return args.func(args)
    except ImportError as exc:
        if (exc.name or "").split(".")[0] not in PYATS_MODULES:
            raise
        _out(f"pyATS is not installed in this Python ({exc}). Install the collector into a "
             f"virtualenv on Linux (`pip install disconet-collector`); on Windows, use WSL2.")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
