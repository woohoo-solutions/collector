"""Fixture builders shared by the tests: Genie parser shapes and a snapshot
directory in the layout `collect` writes. Every name and value here is
generic or made up; none comes from a real network.
"""

from __future__ import annotations

import json
from pathlib import Path

MONDAY = "2026-08-11T18:00:00+00:00"
TUESDAY = "2026-08-12T09:00:00+00:00"


def cdp_state(entries):
    """Genie 'show cdp neighbors detail' shape."""
    return {
        "total_entries_displayed": len(entries),
        "index": {
            str(number): entry for number, entry in enumerate(entries, start=1)
        },
    }


def lldp_state(entries):
    """Genie 'show lldp neighbors detail' shape."""
    interfaces: dict = {}
    for local, remote_port, neighbour in entries:
        interfaces.setdefault(local, {"if_name": local, "port_id": {}})
        interfaces[local]["port_id"][remote_port] = {
            "neighbors": {neighbour["neighbor_id"]: neighbour}
        }
    return {"total_entries": len(entries), "interfaces": interfaces}


def write_snapshot(
    root: Path,
    devices: dict[str, dict],
    created_at: str,
    features: list[str] | None = None,
    mode: str = "loose",
    **manifest_extra,
) -> Path:
    """A snapshot on disk, in the layout `collect` writes.

    ``devices`` maps a device name to a dict of command -> status. A command
    with a real status gets state and raw files written for it, so the merge is
    exercised against files that actually exist rather than against a manifest
    alone.
    """
    root.mkdir(parents=True, exist_ok=True)
    entries: dict[str, dict] = {}
    for device, commands in devices.items():
        command_entries = []
        connected = bool(commands)
        for index, (command, status) in enumerate(commands.items()):
            slug = command.replace(" ", "-")
            entry = {
                "command": command,
                "status": status,
                "state_file": None,
                "raw_file": None,
                "redacted_lines": 1,
                "seconds": 0.5,
                "detail": None,
            }
            if status != "failed":
                state = f"{device}/state/{slug}.json"
                raw = f"{device}/raw/{slug}.txt"
                (root / device / "state").mkdir(parents=True, exist_ok=True)
                (root / device / "raw").mkdir(parents=True, exist_ok=True)
                (root / state).write_text(
                    json.dumps({"device": device, "command": command, "n": index}),
                    encoding="utf-8",
                )
                (root / raw).write_text(f"{device}: {command}\n", encoding="utf-8")
                entry["state_file"] = state
                entry["raw_file"] = raw
            command_entries.append(entry)
        entries[device] = {
            "name": device,
            "os": "iosxr",
            "platform": "ncs540",
            "connected": connected,
            "error": None if connected else 'connect failed: failed to connect',
            "connect_log": None,
            "probed": False,
            "commands": command_entries,
        }
    manifest = {
        "disconet_version": "0.1.0",
        "snapshot_id": root.name,
        "created_at": created_at,
        "testbed": "testbed.yaml",
        "commands_file": "disconet/commands.yaml",
        "requested_devices": list(devices),
        "connect_timeout": 90,
        "command_timeout": 120,
        "verify_reachability": False,
        "features": ["isis", "mpls"] if features is None else features,
        "features_skipped": [],
        "mode": mode,
        "double_enable": False,
        "devices": entries,
        "summary": {"devices_total": len(entries)},
    }
    manifest.update(manifest_extra)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (root / "collect.log").write_text(f"run {root.name}\n", encoding="utf-8")
    return root
