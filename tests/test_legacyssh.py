"""DiscoNet's own ssh client, for the devices OpenSSH refuses for a short RSA host key.

OpenSSH will not talk to an RSA host key under 1024 bits, and classic IOS
generated 512-bit keys by default. The collector logs in to such a device
through netstate.legacyssh instead of leaving it out, held to the same pins.
"""

from __future__ import annotations

import asyncio
import os
import pty
import select
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from netstate import collector, hostkeys, legacyssh

from tests.test_collector_enable import (
    CONNECT_FAILED,
    DoubleEnableTestCase,
    RecordingDevice,
    SHORT_HOST_KEY,
)

# A 512-bit RSA host key, as `ssh-keyscan` would print it if it could.
KEY_512 = (
    "AAAAB3NzaC1yc2EAAAADAQABAAAAQQDgtTm0/ErC/FbY5q62yyxexpX2iUkDqqSGN0W5X9jlfBecqKK"
    "V82c3BSU17CL+pymM2FjlO0gLoceF+jrU/YKh"
)
OTHER_512 = KEY_512.replace("AAAAQQDgtTm0", "AAAAQQDgtTm1")
CREDENTIALS = {"default": {"username": "netops", "password": "pw"}}


class TheKeySize(unittest.TestCase):
    def test_an_rsa_blob_is_measured_without_loading_it(self):
        self.assertEqual(hostkeys.rsa_bits("ssh-rsa", KEY_512), 512)

    def test_any_other_key_has_no_rsa_size(self):
        self.assertIsNone(hostkeys.rsa_bits("ssh-ed25519", KEY_512))
        self.assertIsNone(hostkeys.rsa_bits("ssh-rsa", "!!!"))


class TheScanFallsBackToDisConetsOwnClient(unittest.TestCase):
    """ssh-keyscan is OpenSSH too: a short RSA key is read by neither."""

    BANNER_ONLY = "# 192.0.2.20:22 SSH-1.99-Cisco-1.25\n"

    def test_a_server_that_spoke_and_gave_ssh_keyscan_no_key_is_read_by_the_relay(self):
        asked = []

        def fallback(address, port, timeout):
            asked.append((address, port))
            return [hostkeys.ScannedKey("192.0.2.20", "ssh-rsa", KEY_512)]

        with self.assertLogs("netstate.hostkeys", "WARNING") as logs:
            keys = hostkeys.scan(
                "192.0.2.20", runner=lambda *a: self.BANNER_ONLY, fallback=fallback
            )
        self.assertEqual([k.key for k in keys], [KEY_512])
        self.assertEqual(asked, [("192.0.2.20", 22)])
        self.assertIn("512 bits", "\n".join(logs.output))

    def test_a_key_ssh_keyscan_read_is_never_read_twice(self):
        fallback = mock.Mock(side_effect=AssertionError("asked again"))
        keys = hostkeys.scan(
            "192.0.2.20", runner=lambda *a: f"192.0.2.20 ssh-rsa {KEY_512}\n", fallback=fallback
        )
        self.assertEqual(len(keys), 1)

    def test_no_banner_means_no_server_and_no_relay_either(self):
        fallback = mock.Mock(side_effect=AssertionError("a silent address was asked again"))
        self.assertEqual(
            hostkeys.scan("192.0.2.20", runner=lambda *a: "Connection timed out\n", fallback=fallback),
            [],
        )

    def test_a_key_for_another_address_is_not_a_pin_candidate(self):
        keys = hostkeys.scan(
            "192.0.2.20", runner=lambda *a: self.BANNER_ONLY,
            fallback=lambda *a: [hostkeys.ScannedKey("192.0.2.99", "ssh-rsa", KEY_512)],
        )
        self.assertEqual(keys, [])


class TheRelayIsHeldToThePins(unittest.TestCase):
    """Refused as OpenSSH refuses, in its words, so the collector's diagnosis reads it unchanged."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.pins = Path(directory.name) / "known_hosts"
        self.pins.write_text(f"192.0.2.20 ssh-rsa {KEY_512}\n")
        self.key = mock.Mock(public_data=__import__("base64").b64decode(KEY_512))
        self.key.get_algorithm.return_value = "ssh-rsa"

    def test_the_pinned_key_is_let_through(self):
        self.assertIsNone(legacyssh._host_key_refusal(self.pins, "192.0.2.20", 22, self.key))

    def test_an_unpinned_key_is_refused_as_strict_checking_refuses_it(self):
        refusal = legacyssh._host_key_refusal(self.pins, "192.0.2.21", 22, self.key)
        self.assertIn("No RSA host key is known for 192.0.2.21 and you have requested strict checking", refusal)
        hint = collector.connect_failure_hint(CONNECT_FAILED, False, refusal, known_hosts=self.pins)
        self.assertIn("not pinned", hint)

    def test_a_changed_key_is_refused_as_a_changed_key(self):
        self.pins.write_text(f"192.0.2.20 ssh-rsa {OTHER_512}\n")
        refusal = legacyssh._host_key_refusal(self.pins, "192.0.2.20", 22, self.key)
        self.assertIn("REMOTE HOST IDENTIFICATION HAS CHANGED", refusal)
        hint = collector.connect_failure_hint(CONNECT_FAILED, False, refusal, known_hosts=self.pins)
        self.assertIn("has changed since it was pinned", hint)

    def test_the_command_names_the_pins_and_the_login_and_never_a_password(self):
        command = legacyssh.relay_command("192.0.2.20", 2222, "netops", self.pins)
        self.assertIn(legacyssh.RELAY_ENTRY, command)
        self.assertIn("-l netops -p 2222", command)
        self.assertIn(str(self.pins.resolve()), command)
        self.assertNotIn("pw", command.split())

    def test_legacy_algorithms_come_after_the_modern_ones(self):
        if not legacyssh.available():
            self.skipTest("asyncssh is not installed")
        kex = legacyssh.connect_options()["kex_algs"]
        self.assertIn("diffie-hellman-group1-sha1", kex)
        self.assertLess(kex.index("curve25519-sha256"), kex.index("diffie-hellman-group1-sha1"))
        self.assertIn("ssh-rsa", legacyssh.connect_options()["server_host_key_algs"])


def relay_device(**connection) -> RecordingDevice:
    return RecordingDevice(
        credentials=CREDENTIALS,
        connections={"cli": {"protocol": "ssh", "ip": "192.0.2.20", **connection}},
    )


class WhenTheRelayCanTakeTheLoginOver(DoubleEnableTestCase):
    def setUp(self):
        super().setUp()
        self.pins = self.root / "known_hosts"
        self.pins.write_text(f"192.0.2.20 ssh-rsa {KEY_512}\n")
        patcher = mock.patch.object(legacyssh, "available", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_device_behind_a_jump_host_is_not_relayed(self):
        reason = collector.relay_connection(relay_device(proxy="jumphost"), self.pins)
        self.assertIsInstance(reason, str)
        self.assertIn("jump host", reason)

    def test_without_asyncssh_the_reason_is_named(self):
        with mock.patch.object(legacyssh, "available", return_value=False):
            reason = collector.relay_connection(relay_device(), self.pins)
        self.assertIn("asyncssh", reason)

    def test_telnet_and_a_literal_command_are_left_alone(self):
        self.assertIsInstance(collector.relay_connection(relay_device(protocol="telnet"), self.pins), str)
        self.assertIsInstance(collector.relay_connection(relay_device(command="mock_cli"), self.pins), str)

    def test_the_plan_points_the_connection_at_the_relay_and_knows_the_key_size(self):
        device = relay_device()
        plan = collector.relay_connection(device, self.pins)
        self.assertEqual(plan.bits, 512)
        plan.apply()
        self.assertIn("netstate.legacyssh", device.connections["cli"]["command"])
        self.assertIn("-l netops", device.connections["cli"]["command"])
        plan.undo()
        self.assertNotIn("command", device.connections["cli"])


class TheCollectorFallsBackByItself(DoubleEnableTestCase):
    """No flag, no re-run: the same collection logs in through the relay."""

    def setUp(self):
        super().setUp()
        self.pins = self.root / "known_hosts"
        self.pins.write_text(f"192.0.2.20 ssh-rsa {KEY_512}\n")
        for name, value in (("available", True),):
            patcher = mock.patch.object(legacyssh, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(collector, "port_answers", side_effect=AssertionError("telnet probed"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def device(self, *dialogs, errors=(), **connection):
        device = relay_device(**connection)
        device.dialogs = list(dialogs)
        device.connect_errors = list(errors)
        device.default._logfile = str(self.root / "dialog.log")
        return device

    def collect(self, device, **kwargs):
        kwargs.setdefault("known_hosts", self.pins)
        return super().collect(device, **kwargs)

    def test_a_short_host_key_is_logged_into_through_the_relay(self):
        device = self.device(SHORT_HOST_KEY, "sw-1#\n", errors=[CONNECT_FAILED, None])
        outcome = self.collect(device)

        self.assertTrue(outcome.connected)
        self.assertIsNone(outcome.error)
        self.assertEqual(device.commands[:3], ["<connect>", "<destroy>", "<connect>"])
        self.assertIn("netstate.legacyssh", device.connections["cli"]["command"])
        self.assertEqual(outcome.ssh_client, legacyssh.CLIENT_NAME)
        self.assertEqual(outcome.as_dict()["ssh_client"], legacyssh.CLIENT_NAME)
        self.assertEqual(outcome.as_dict()["host_key_bits"], 512)
        self.assertIsNone(outcome.protocol)

    def test_no_opt_in_is_needed(self):
        device = self.device(SHORT_HOST_KEY, "sw-1#\n", errors=[CONNECT_FAILED, None])
        outcome = self.collect(device, allow_legacy_ssh=False, allow_telnet=False)
        self.assertTrue(outcome.connected)

    def test_a_password_the_device_refuses_through_the_relay_is_that_login_s_failure(self):
        refused = "Password: \nPermission denied, please try again.\nPassword: \n"
        device = self.device(
            SHORT_HOST_KEY, refused, errors=[CONNECT_FAILED, RuntimeError("Bad Password")]
        )
        outcome = self.collect(device, allow_telnet=True)

        self.assertFalse(outcome.connected)
        self.assertIn("Bad Password", outcome.error)
        self.assertIn("DiscoNet's own ssh client", outcome.error)
        # Not the short-key hint, and not legacy algorithms: the relay
        # offered those, and finalize must not suggest them again.
        self.assertNotIn("under 1024 bits", outcome.error)
        self.assertEqual(outcome.ssh_client, legacyssh.CLIENT_NAME)

    def test_behind_a_jump_host_the_report_says_why_the_relay_was_not_used(self):
        device = self.device(SHORT_HOST_KEY, errors=[CONNECT_FAILED], proxy="jumphost")
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>"])
        self.assertIn("under 1024 bits", outcome.error)
        self.assertIn("jump host's ssh client", outcome.error)

    def test_any_other_refusal_is_never_relayed(self):
        device = self.device("Permission denied, please try again.\n", errors=[CONNECT_FAILED])
        outcome = self.collect(device)
        self.assertEqual(device.commands, ["<connect>"])
        self.assertIsNone(outcome.ssh_client)


@unittest.skipUnless(legacyssh.available() and shutil.which("openssl"), "needs asyncssh and openssl")
class TheRelayLogsInToA512BitDevice(unittest.TestCase):
    """End to end: a real ssh server offering only what old IOS offers.

    A 512-bit RSA host key, Diffie-Hellman group 1, `ssh-rsa` and CBC: the
    relay is spawned on a terminal, as unicon spawns it, asks for the
    password at its own prompt, and relays the session both ways.
    """

    def setUp(self):
        import asyncssh

        # The server half runs in this process; the relay quiets its own.
        legacyssh._quiet()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)
        subprocess.run(
            ["openssl", "genrsa", "-traditional", "-out", str(self.dir / "host.pem"), "512"],
            check=True, capture_output=True,
        )
        host_key = asyncssh.read_private_key(str(self.dir / "host.pem"))
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                return password == "pw"

        async def shell(process):
            process.stdout.write("\r\nR1#")
            while True:
                line = await process.stdin.readline()
                if not line or line.strip() == "exit":
                    break
                answer = "Cisco IOS Software, Version 12.2(55)SE\r\n" if line.startswith("show version") else ""
                process.stdout.write(line.strip() + "\r\n" + answer + "R1#")
            process.exit(0)

        async def start():
            self.server = await asyncssh.create_server(
                Server, "127.0.0.1", 0, server_host_keys=[host_key],
                process_factory=shell, kex_algs=["diffie-hellman-group1-sha1"],
                encryption_algs=["aes128-cbc"],
                mac_algs=["hmac-sha1"],
            )
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(start())
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.assertTrue(ready.wait(10), "the test server did not start")
        self.addCleanup(self.stop)
        public = host_key.export_public_key("openssh").decode().split()
        self.pins = self.dir / "known_hosts"
        self.pins.write_text(f"[127.0.0.1]:{self.port} {public[0]} {public[1]}\n")

    def stop(self):
        self.loop.call_soon_threadsafe(self.server.close)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()

    def spawn(self):
        controller, terminal = pty.openpty()
        command = legacyssh.relay_command("127.0.0.1", self.port, "netops", self.pins)
        process = subprocess.Popen(
            __import__("shlex").split(command), stdin=terminal, stdout=terminal, stderr=terminal,
            cwd=Path(__file__).resolve().parents[1], close_fds=True,
        )
        os.close(terminal)
        self.addCleanup(lambda: (process.poll() is None and process.kill(), os.close(controller)))
        return process, controller

    @staticmethod
    def read_until(fd, text, timeout=20):
        seen = b""
        deadline = time.monotonic() + timeout
        while text.encode() not in seen:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"never saw {text!r}; saw {seen!r}")
            ready, _, _ = select.select([fd], [], [], remaining)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                seen += chunk
        return seen.decode(errors="replace")

    def test_the_relay_asks_for_the_password_and_carries_the_session(self):
        process, fd = self.spawn()
        # The device's own keyboard-interactive prompt, nothing before it:
        # whatever the relay printed first would be in unicon's dialog.
        self.assertEqual(self.read_until(fd, "Password:").strip(), "Password:")
        os.write(fd, b"pw\r")
        self.read_until(fd, "R1#")
        os.write(fd, b"show version\r")
        self.assertIn("Version 12.2(55)SE", self.read_until(fd, "SE"))
        os.write(fd, b"exit\r")
        self.assertEqual(process.wait(20), 0)

    def test_a_wrong_password_is_asked_again_as_openssh_asks_it(self):
        process, fd = self.spawn()
        self.read_until(fd, "Password:")
        os.write(fd, b"wrong\r")
        self.assertIn("Permission denied, please try again.", self.read_until(fd, "Password:"))
        process.kill()
        process.wait(5)

    def test_an_unpinned_key_ends_it_before_the_password_is_asked(self):
        self.pins.write_text("")
        process, fd = self.spawn()
        said = self.read_until(fd, "Host key verification failed.")
        self.assertIn("you have requested strict checking", said)
        self.assertNotIn("Password", said)
        self.assertEqual(process.wait(20), legacyssh.EXIT_REFUSED)

    def test_the_scan_reads_the_key_ssh_keyscan_cannot(self):
        keys = legacyssh.scan("127.0.0.1", self.port)
        self.assertEqual(len(keys), 1)
        self.assertEqual(hostkeys.rsa_bits(keys[0].key_type, keys[0].key), 512)


if __name__ == "__main__":
    unittest.main()
