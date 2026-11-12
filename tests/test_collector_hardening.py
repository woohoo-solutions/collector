"""WS1: the Collector, hardened before prospects run it themselves.

Four gaps, each with its own tests:

a) Legacy SSH and telnet are opt-in. A refused negotiation is reported with
   the flag that would try it; nothing is retried, no TCP/23 probe is made
   and no telnet login is attempted without --allow-telnet.
b) Host keys are strict: every ssh session spawned here runs against the
   estate's own known_hosts, a first-use prompt pins only what an engineer
   confirmed, and unicon is never let answer "yes" to an unknown key.
c) Redaction: -v echoes the login dialog redacted instead of unicon's raw
   stream, the testbed's own and its servers' credentials are scrubbed, and
   connect.log.tmp is created 600 and removed on every exit path.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netstate import collector, hostkeys
from netstate.collector import REDACTION_MARKER
from tests.test_collector_enable import (
    CONNECT_FAILED, KEX_OPTION, KEX_REFUSED, SHORT_HOST_KEY, DoubleEnableTestCase, RecordingDevice,
)

try:  # the recorded-dialog tests drive the real unicon; the rest need none of it
    import unicon  # noqa: F401
    HAVE_UNICON = True
except Exception:  # noqa: BLE001 - any import failure means "not here"
    HAVE_UNICON = False


# What OpenSSH 9.x prints, verbatim, when an IOS 12.2 switch offers only
# ssh-rsa / group1 and a 512-bit key: the dialogs these tests replay.
RECORDED_KEX_REFUSAL = (
    "+++ connection to spawn: ssh -l netops 192.0.2.12, id: 140230 +++\n"
    "Unable to negotiate with 192.0.2.12 port 22: no matching key exchange method found. "
    "Their offer: diffie-hellman-group1-sha1,diffie-hellman-group14-sha1\n"
)
RECORDED_SHORT_KEY_REFUSAL = (
    "+++ connection to spawn: ssh -l netops 192.0.2.12, id: 140231 +++\n"
    "ssh_dispatch_run_fatal: Connection to 192.0.2.12 port 22: Invalid key length\n"
)


class Ports:
    """Every TCP connect this process attempts, by port, refused for 23."""

    def __init__(self):
        self.asked: list[int] = []

    def __call__(self, address, *args, **kwargs):
        host, port = address
        self.asked.append(int(port))
        raise OSError("refused by the test")


class OptInTestCase(DoubleEnableTestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(collector, "client_algorithms", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.ports = Ports()
        patcher = mock.patch("socket.create_connection", side_effect=self.ports)
        patcher.start()
        self.addCleanup(patcher.stop)

    def device(self, *dialogs, errors=(), connection=None, **kwargs):
        connection = dict(connection or {"protocol": "ssh", "ip": "192.0.2.12"})
        device = RecordingDevice(
            dialogs=dialogs, connect_errors=list(errors), connections={"cli": connection}, **kwargs,
        )
        device.default._logfile = str(self.root / "dialog.log")
        return device


class TestNoTelnetWithoutTheFlag(OptInTestCase):
    """The recorded dialogs of a device no ssh client can reach: nothing goes to TCP/23."""

    def test_a_recorded_short_key_refusal_tries_no_telnet_at_all(self):
        device = self.device(RECORDED_SHORT_KEY_REFUSAL, errors=[CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertFalse(outcome.connected)
        # One login, over ssh, and nothing after it: no destroy, no second
        # connect, no probe of port 23 and no socket opened to it.
        self.assertEqual(device.commands, ["<connect>"])
        self.assertEqual(self.ports.asked, [])
        self.assertEqual(device.connections["cli"]["protocol"], "ssh")
        self.assertNotIn("port", device.connections["cli"])
        self.assertIsNone(outcome.protocol)
        self.assertIn("telnet was not tried", outcome.error)
        self.assertIn("--allow-telnet", outcome.error)
        self.assertIn("allow_telnet: true", outcome.error)

    def test_a_recorded_kex_refusal_is_not_retried_and_names_both_flags(self):
        device = self.device(RECORDED_KEX_REFUSAL, errors=[CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>"])
        self.assertEqual(self.ports.asked, [])
        self.assertNotIn("ssh_options", device.connections["cli"])
        self.assertIsNone(outcome.ssh_options)
        self.assertIn("share no algorithm", outcome.error)
        self.assertIn(f"not logged in again with {KEX_OPTION}", outcome.error)
        self.assertIn("--allow-legacy-ssh", outcome.error)
        self.assertIn("--allow-telnet", outcome.error)

    def test_the_legacy_flag_alone_still_tries_no_telnet(self):
        device = self.device(KEX_REFUSED, SHORT_HOST_KEY, errors=[CONNECT_FAILED, CONNECT_FAILED])
        outcome = self.collect(device, allow_legacy_ssh=True)

        self.assertEqual(device.commands, ["<connect>", "<destroy>", "<connect>"])
        self.assertEqual(self.ports.asked, [])
        self.assertIn("telnet was not tried", outcome.error)

    def test_with_the_flag_port_23_is_probed_and_telnet_tried(self):
        with mock.patch.object(collector, "port_answers", return_value=True) as probe:
            device = self.device(SHORT_HOST_KEY, "sw-1#\n", errors=[CONNECT_FAILED, None])
            outcome = self.collect(device, allow_telnet=True)

        probe.assert_called_once_with("192.0.2.12", 23)
        self.assertEqual(outcome.protocol, "telnet")

    def test_a_device_the_testbed_declares_as_telnet_needs_no_flag(self):
        # The block says telnet: that is the operator's explicit choice.
        device = self.device("sw-1#\n", errors=[None], connection={"protocol": "telnet", "ip": "192.0.2.12", "port": 23})
        outcome = self.collect(device)

        self.assertTrue(outcome.connected)
        self.assertEqual(device.commands[0], "<connect>")


class TestTheTestbedKeys(OptInTestCase):
    """`allow_legacy_ssh` / `allow_telnet` under `custom:`, the device's or the testbed's."""

    def test_the_device_s_own_key_allows_the_legacy_retry(self):
        device = self.device(KEX_REFUSED, "pe-1#\n", errors=[CONNECT_FAILED, None], custom={"allow_legacy_ssh": True})
        outcome = self.collect(device)

        self.assertTrue(outcome.connected)
        self.assertEqual(outcome.ssh_options, KEX_OPTION)

    def test_the_testbed_s_key_allows_the_telnet_fallback(self):
        testbed = SimpleNamespace(custom={"allow_telnet": True})
        with mock.patch.object(collector, "port_answers", return_value=True):
            device = self.device(SHORT_HOST_KEY, "sw-1#\n", errors=[CONNECT_FAILED, None], testbed=testbed)
            outcome = self.collect(device)

        self.assertEqual(outcome.protocol, "telnet")

    def test_a_word_that_is_not_yaml_true_is_not_a_yes(self):
        for value in ("true", "yes", 1, "on"):
            with self.subTest(value=value):
                device = self.device(KEX_REFUSED, errors=[CONNECT_FAILED], custom={"allow_legacy_ssh": value})
                self.assertFalse(collector.opted_in(device, collector.ALLOW_LEGACY_SSH_KEY))
                outcome = self.collect(device)
                self.assertEqual(device.commands, ["<connect>"])
                self.assertIn("--allow-legacy-ssh", outcome.error)


# --------------------------------------------------------------------------
# b) Host keys
# --------------------------------------------------------------------------

ED25519_LINE_KEY = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()


class TestThePinFile(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.pins = self.dir / "known_hosts"

    def test_it_lives_beside_the_testbed(self):
        self.assertEqual(hostkeys.known_hosts_path(self.dir / "testbed.yaml"), self.pins.resolve())

    def test_plain_ported_and_hashed_entries_are_read_and_markers_are_not(self):
        salt = os.urandom(20)
        digest = hmac.new(salt, b"192.0.2.30", hashlib.sha1).digest()
        hashed = f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()}"
        self.pins.write_text(textwrap.dedent(f"""\
            # a comment
            192.0.2.10,r1 ssh-ed25519 {ED25519_LINE_KEY}
            [192.0.2.20]:2222 ssh-ed25519 {ED25519_LINE_KEY}
            {hashed} ssh-ed25519 {ED25519_LINE_KEY}
            @revoked 192.0.2.40 ssh-ed25519 {ED25519_LINE_KEY}
            """))
        self.assertTrue(hostkeys.is_pinned(self.pins, "192.0.2.10"))
        self.assertFalse(hostkeys.is_pinned(self.pins, "192.0.2.20"))
        self.assertTrue(hostkeys.is_pinned(self.pins, "192.0.2.20", 2222))
        self.assertTrue(hostkeys.is_pinned(self.pins, "192.0.2.30"))
        self.assertFalse(hostkeys.is_pinned(self.pins, "192.0.2.40"))
        self.assertFalse(hostkeys.is_pinned(self.dir / "missing", "192.0.2.10"))

    def test_a_pin_is_written_owner_only_and_says_who_and_when(self):
        key = hostkeys.ScannedKey("192.0.2.10", "ssh-ed25519", ED25519_LINE_KEY)
        hostkeys.pin(self.pins, "R1", [key])
        hostkeys.pin(self.pins, "R2", [hostkeys.ScannedKey("192.0.2.11", "ssh-ed25519", ED25519_LINE_KEY)])

        self.assertEqual(stat.S_IMODE(self.pins.stat().st_mode), 0o600)
        text = self.pins.read_text()
        self.assertIn("# R1: pinned by DiscoNet", text)
        self.assertIn(f"192.0.2.10 ssh-ed25519 {ED25519_LINE_KEY}\n", text)
        self.assertTrue(hostkeys.is_pinned(self.pins, "192.0.2.11"))

    @unittest.skipUnless(shutil.which("ssh-keygen"), "no ssh-keygen here")
    def test_the_fingerprint_is_the_one_ssh_keygen_prints(self):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.dir / "id")],
            check=True, capture_output=True,
        )
        key_type, key = (self.dir / "id.pub").read_text().split()[:2]
        printed = subprocess.run(
            ["ssh-keygen", "-l", "-E", "sha256", "-f", str(self.dir / "id.pub")],
            check=True, capture_output=True, text=True,
        ).stdout.split()[1]
        self.assertEqual(hostkeys.fingerprint(key), printed)

    def test_only_well_formed_lines_for_this_address_are_scan_results(self):
        output = textwrap.dedent(f"""\
            # 192.0.2.10:22 SSH-2.0-Cisco-1.25
            192.0.2.10 ssh-ed25519 {ED25519_LINE_KEY}
            192.0.2.99 ssh-ed25519 {ED25519_LINE_KEY}
            192.0.2.10 not-a-key-type {ED25519_LINE_KEY}
            192.0.2.10 ssh-rsa !!!notbase64!!!
            """)
        keys = hostkeys.scan("192.0.2.10", runner=lambda address, port, timeout: output)
        self.assertEqual([(k.pattern, k.key_type) for k in keys], [("192.0.2.10", "ssh-ed25519")])

    # What an NCS 540 on IOS-XR 7.x printed to `ssh-keyscan` asking for every
    # type at once (stdout and stderr together), and to `ssh-keyscan -t ed25519`.
    XR_BURST = textwrap.dedent("""\
        192.0.2.15: Connection closed by remote host
        192.0.2.15: Connection closed by remote host
        192.0.2.15: Connection closed by remote host
        192.0.2.15: Connection closed by remote host
        # 192.0.2.15:22 SSH-2.0-OpenSSH_8.0 PKIX[12.1]
        """)
    XR_ED25519 = (
        "# 192.0.2.15:22 SSH-2.0-OpenSSH_8.0 PKIX[12.1]\n"
        f"192.0.2.15 ssh-ed25519 {ED25519_LINE_KEY}\n"
    )

    def test_a_server_that_drops_the_parallel_burst_is_asked_one_type_at_a_time(self):
        asked = []

        def runner(address, port, timeout, key_type=None):
            asked.append(key_type)
            return self.XR_ED25519 if key_type == "ed25519" else self.XR_BURST

        keys = hostkeys.scan("192.0.2.15", runner=runner)
        self.assertEqual([(k.pattern, k.key_type) for k in keys], [("192.0.2.15", "ssh-ed25519")])
        self.assertEqual(asked, [None, "ed25519"])

    def test_one_type_at_a_time_goes_on_until_one_answers(self):
        asked = []

        def runner(address, port, timeout, key_type=None):
            asked.append(key_type)
            if key_type == "rsa":
                return f"192.0.2.15 ssh-rsa {ED25519_LINE_KEY}\n"
            return self.XR_BURST

        keys = hostkeys.scan("192.0.2.15", runner=runner)
        self.assertEqual([k.key_type for k in keys], ["ssh-rsa"])
        self.assertEqual(asked, [None, "ed25519", "rsa"])

    def test_no_banner_means_no_server_and_no_second_scan(self):
        asked = []

        def runner(address, port, timeout, key_type=None):
            asked.append(key_type)
            return "192.0.2.15: Connection timed out\n"

        self.assertEqual(hostkeys.scan("192.0.2.15", runner=runner), [])
        self.assertEqual(asked, [None])

    def test_a_server_that_answers_no_single_type_reads_nothing(self):
        asked = []

        def runner(address, port, timeout, key_type=None):
            asked.append(key_type)
            return self.XR_BURST

        self.assertEqual(hostkeys.scan("192.0.2.15", runner=runner), [])
        self.assertEqual(asked, [None, *hostkeys.SEQUENTIAL_KEY_TYPES])

    def test_the_keyscan_command_asks_for_one_type_only_when_told(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with mock.patch.object(hostkeys.subprocess, "run", side_effect=fake_run):
            hostkeys._run_keyscan("192.0.2.15", 22, 5)
            hostkeys._run_keyscan("192.0.2.15", 22, 5, "ed25519")
        self.assertEqual(calls[0], ["ssh-keyscan", "-T", "5", "-p", "22", "192.0.2.15"])
        self.assertEqual(calls[1], ["ssh-keyscan", "-T", "5", "-p", "22", "-t", "ed25519", "192.0.2.15"])


def pyats_device(name, **connection):
    return SimpleNamespace(name=name, connections={"cli": dict(connection)})


class TestThePolicyOnAConnection(unittest.TestCase):
    PINS = Path("/estates/lab/known_hosts")

    def test_a_direct_ssh_connection_is_held_strictly_to_the_pin_file(self):
        device = pyats_device("R1", protocol="ssh", ip="192.0.2.10")
        hostkeys.apply(device, self.PINS)
        options = device.connections["cli"]["ssh_options"]
        self.assertEqual(
            options,
            "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/estates/lab/known_hosts "
            "-o GlobalKnownHostsFile=/dev/null",
        )

    def test_it_goes_in_front_so_a_testbed_s_own_no_cannot_win_and_is_reported(self):
        device = pyats_device(
            "R1", protocol="ssh", ip="192.0.2.10",
            ssh_options="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        )
        overridden = hostkeys.apply(device, self.PINS)
        options = device.connections["cli"]["ssh_options"]
        self.assertTrue(options.startswith("-o StrictHostKeyChecking=yes "))
        self.assertEqual(sorted(overridden), ["StrictHostKeyChecking", "UserKnownHostsFile"])
        # Applied twice, it is there once.
        hostkeys.apply(device, self.PINS)
        self.assertEqual(device.connections["cli"]["ssh_options"].count("StrictHostKeyChecking=yes"), 1)

    def test_a_hop_typed_on_a_jump_host_and_a_telnet_session_are_left_alone(self):
        hop = pyats_device("R1", protocol="ssh", ip="192.0.2.10", proxy="jump")
        telnet = pyats_device("R2", protocol="telnet", ip="192.0.2.11", port=23)
        hostkeys.apply(hop, self.PINS)
        hostkeys.apply(telnet, self.PINS)
        self.assertNotIn("ssh_options", hop.connections["cli"])
        self.assertNotIn("ssh_options", telnet.connections["cli"])

    def test_a_path_with_a_space_is_quoted_for_the_spawn(self):
        options = hostkeys.policy_options("/mnt/c/Users/A B/known_hosts")
        self.assertIn("UserKnownHostsFile='/mnt/c/Users/A B/known_hosts'", options)

    def test_what_a_run_records_has_the_policy_taken_off(self):
        prefix = hostkeys.policy_options(self.PINS)
        self.assertEqual(hostkeys.without_policy(f"{prefix} {KEX_OPTION}", self.PINS), KEX_OPTION)
        self.assertIsNone(hostkeys.without_policy(prefix, self.PINS))
        self.assertEqual(hostkeys.without_policy(KEX_OPTION, self.PINS), KEX_OPTION)


class TestTheFirstUsePrompt(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pins = Path(tmp.name) / "known_hosts"
        self.scanned: list[tuple[str, int]] = []

    def scanner(self, address, port):
        self.scanned.append((address, port))
        return [hostkeys.ScannedKey(hostkeys.host_pattern(address, port), "ssh-ed25519", ED25519_LINE_KEY)]

    def test_a_confirmed_key_is_pinned_and_a_declined_one_is_not(self):
        devices = [pyats_device("R1", ip="192.0.2.10"), pyats_device("R2", ip="192.0.2.11")]
        asked = []

        def confirm(target, keys):
            asked.append((target.device, keys[0].fingerprint))
            return target.device == "R1"

        outcome = hostkeys.confirm_first_use(devices, self.pins, confirm, scanner=self.scanner)

        self.assertEqual(outcome, {"192.0.2.10": "pinned", "192.0.2.11": "declined"})
        self.assertEqual([name for name, _ in asked], ["R1", "R2"])
        self.assertTrue(asked[0][1].startswith("SHA256:"))
        self.assertTrue(hostkeys.is_pinned(self.pins, "192.0.2.10"))
        self.assertFalse(hostkeys.is_pinned(self.pins, "192.0.2.11"))

    def test_a_pinned_key_is_neither_scanned_nor_asked_about(self):
        hostkeys.pin(self.pins, "R1", [hostkeys.ScannedKey("192.0.2.10", "ssh-ed25519", ED25519_LINE_KEY)])
        confirm = mock.Mock(side_effect=AssertionError("asked about a pinned key"))
        hostkeys.confirm_first_use([pyats_device("R1", ip="192.0.2.10")], self.pins, confirm, scanner=self.scanner)
        self.assertEqual(self.scanned, [])

    def test_a_key_that_cannot_be_read_is_not_asked_about_and_nothing_is_pinned(self):
        confirm = mock.Mock(side_effect=AssertionError("asked with no key"))
        outcome = hostkeys.confirm_first_use(
            [pyats_device("R1", ip="192.0.2.10")], self.pins, confirm, scanner=lambda a, p: [],
        )
        self.assertEqual(outcome, {"192.0.2.10": "unreadable"})
        self.assertFalse(self.pins.exists())


class TestTheRecordedOptionsLeaveThePolicyOut(OptInTestCase):
    def test_finalize_is_given_the_legacy_options_without_this_machine_s_pin_path(self):
        pins = self.root / "known_hosts"
        device = self.device(KEX_REFUSED, "pe-1#\n", errors=[CONNECT_FAILED, None])
        hostkeys.apply(device, pins)
        outcome = self.collect(device, allow_legacy_ssh=True, known_hosts=pins)

        self.assertTrue(outcome.connected)
        self.assertEqual(outcome.ssh_options, KEX_OPTION)
        # The session itself kept the policy in front of what was added.
        self.assertTrue(device.connections["cli"]["ssh_options"].startswith(hostkeys.policy_options(pins)))


class TestTheHostKeyAdvice(unittest.TestCase):
    def test_a_strict_refusal_names_the_pin_file_and_the_way_to_pin(self):
        hint = collector.connect_failure_hint(
            RuntimeError("failed to connect to R1"), False,
            "No ED25519 host key is known for 192.0.2.10 and you have requested strict checking.\n"
            "Host key verification failed.\n",
            known_hosts="/estates/lab/known_hosts",
        )
        self.assertIn("not pinned in /estates/lab/known_hosts", hint)
        self.assertIn("never accepts a key by itself", hint)


@unittest.skipUnless(HAVE_UNICON and sys.platform != "win32", "the recorded dialog drives the real unicon")
class TestUniconNeverAnswersYes(unittest.TestCase):
    """A recorded OpenSSH host-key question, played to the real unicon.

    The fake ssh prints the question OpenSSH asks about an unseen key and
    writes down what it was answered. unicon's own connection dialog answers
    "yes" — proved first, so the test can tell — and the dialog every
    DiscoNet login carries answers "no".
    """

    QUESTION_SCRIPT = textwrap.dedent('''\
        import sys
        record = sys.argv[1]
        sys.stdout.write(
            "The authenticity of host '192.0.2.7 (192.0.2.7)' can't be established.\\r\\n"
            "ED25519 key fingerprint is SHA256:Xo3nVf0V4b2tF6h7Qy1y8m2c1zq0rCq1H2lJQ7wQK8E.\\r\\n"
            "This key is not known by any other names.\\r\\n"
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
        sys.stdout.flush()
        answer = sys.stdin.readline().strip()
        with open(record, "a") as handle:
            handle.write(answer + "\\n")
        if answer == "yes":
            sys.stdout.write("Warning: Permanently added '192.0.2.7' (ED25519) to the list of known hosts.\\r\\n")
            sys.stdout.write("Password: ")
            sys.stdout.flush()
            sys.stdin.readline()
            sys.stdout.write("\\r\\nR1#")
            sys.stdout.flush()
            sys.stdin.readline()
            sys.exit(0)
        sys.stdout.write("Host key verification failed.\\r\\n")
        sys.stdout.flush()
        sys.exit(255)
        ''')

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.script = self.dir / "fake_ssh.py"
        self.script.write_text(self.QUESTION_SCRIPT)

    def login(self, **extra) -> tuple[bool, list[str]]:
        from unicon import Connection

        record = self.dir / f"answers-{len(list(self.dir.iterdir()))}.txt"
        connection = Connection(
            hostname="R1", start=[f"{sys.executable} {self.script} {record}"], os="generic",
            credentials={"default": {"username": "u", "password": "p"}},
            connection_timeout=15, log_stdout=False, logfile=str(self.dir / "unicon.log"),
            learn_hostname=False, init_exec_commands=[], init_config_commands=[], **extra,
        )
        try:
            connection.connect()
            connected = True
        except Exception:  # noqa: BLE001 - the refusal is the expected outcome
            connected = False
        finally:
            try:
                connection.disconnect()
            except Exception:  # noqa: BLE001
                pass
        return connected, record.read_text().split() if record.exists() else []

    def test_unicon_on_its_own_says_yes_which_is_why_this_exists(self):
        connected, answers = self.login()
        self.assertEqual(answers, ["yes"])
        self.assertTrue(connected)

    def test_the_login_dialog_answers_no_and_the_login_stops(self):
        connected, answers = self.login(connect_reply=collector.login_dialog(()))
        self.assertEqual(answers, ["no"])
        self.assertFalse(connected)

    def test_declared_login_prompts_do_not_displace_the_refusal(self):
        prompt = collector.LoginPrompt(pattern=r"continue connecting", response="yes")
        connected, answers = self.login(connect_reply=collector.login_dialog((prompt,)))
        self.assertEqual(answers, ["no"])
        self.assertFalse(connected)


# --------------------------------------------------------------------------
# c) Redaction and the transcript on disk
# --------------------------------------------------------------------------


class TranscriptDevice(RecordingDevice):
    """Writes each login's dialog where the connect was told to, as unicon does."""

    def __init__(self, *args, dialog="", on_connect=None, **kwargs):
        super().__init__(*args, connections={"cli": {"protocol": "ssh", "ip": "192.0.2.12"}}, **kwargs)
        self.dialog = dialog
        self.on_connect = on_connect
        self.modes: list[int] = []

    def connect(self, **kwargs):
        logfile = Path(kwargs["logfile"])
        self.default._logfile = str(logfile)
        self.modes.append(stat.S_IMODE(logfile.stat().st_mode))
        with open(logfile, "a", encoding="utf-8") as handle:
            handle.write(self.dialog)
        if self.on_connect is not None:
            self.on_connect()
        return super().connect(**kwargs)


class TestTheTranscriptOnDisk(DoubleEnableTestCase):
    def test_connect_log_tmp_exists_owner_only_before_the_first_byte(self):
        device = TranscriptDevice(dialog="pe-1#\n")
        self.collect(device)
        self.assertEqual(device.modes, [0o600])

    def test_it_is_gone_after_an_interrupt_and_its_redacted_copy_kept(self):
        def interrupted():
            raise KeyboardInterrupt

        device = TranscriptDevice(dialog="Password: hunter2-secret\nenable secret 5 $1$abc\n", on_connect=interrupted)
        with self.assertRaises(KeyboardInterrupt):
            self.collect(device, secrets=("hunter2-secret",))

        folder = self.root / device.name
        self.assertFalse((folder / collector.CONNECT_LOG_TEMP).exists())
        kept = (folder / collector.CONNECT_LOG_NAME).read_text()
        self.assertNotIn("hunter2-secret", kept)
        self.assertNotIn("$1$abc", kept)

    def test_a_device_that_never_logged_in_leaves_neither_file(self):
        device = TranscriptDevice(dialog="", connect_errors=[CONNECT_FAILED])
        outcome = self.collect(device)
        folder = self.root / device.name
        self.assertFalse((folder / collector.CONNECT_LOG_TEMP).exists())
        self.assertIsNone(outcome.connect_log)

    def test_the_end_of_a_run_sweeps_a_transcript_its_session_left(self):
        snapshot = self.root / "20261026T000000Z"
        (snapshot / "R1").mkdir(parents=True)
        (snapshot / "R1" / collector.CONNECT_LOG_TEMP).write_text("Password: hunter2-secret\n")
        self.assertEqual(collector.sweep_snapshot_transcripts(snapshot, {"hunter2-secret"}), 1)
        self.assertFalse((snapshot / "R1" / collector.CONNECT_LOG_TEMP).exists())
        self.assertNotIn("hunter2-secret", (snapshot / "R1" / collector.CONNECT_LOG_NAME).read_text())


class TestVerboseIsRedacted(DoubleEnableTestCase):
    DIALOG = (
        "jump-01$ ssh -l netops 192.0.2.12\n"
        "Password: hunter2-secret\n"
        "pe-1#show running-config | include secret\n"
        "enable secret 9 $9$abcdefghijklmnop\n"
        "snmp-server community Publ1cRW RW\n"
        "pe-1#"
    )

    def test_unicon_is_never_asked_to_print_the_session(self):
        device = TranscriptDevice(dialog="pe-1#\n")
        with mock.patch.object(collector, "_echo_to_stdout"):
            self.collect(device, log_stdout=True)
        self.assertTrue(device.connect_kwargs)
        self.assertTrue(all(kwargs["log_stdout"] is False for kwargs in device.connect_kwargs))

    def test_the_echo_shows_the_dialog_with_every_secret_taken_out(self):
        shown: list[str] = []
        device = TranscriptDevice(dialog=self.DIALOG)
        with mock.patch.object(collector, "_echo_to_stdout", side_effect=shown.append):
            self.collect(device, log_stdout=True, secrets=("hunter2-secret",))

        printed = "\n".join(shown)
        self.assertIn("emo_mce_1| jump-01$ ssh -l netops 192.0.2.12", printed)
        self.assertIn(REDACTION_MARKER, printed)
        for secret in ("hunter2-secret", "$9$abcdefghijklmnop", "Publ1cRW"):
            self.assertNotIn(secret, printed)
        # The prompt with no newline after it is shown too, once the login ends.
        self.assertIn("emo_mce_1| pe-1#", printed)

    def test_a_bare_carriage_return_starts_a_line_of_its_own(self):
        path = self.root / "dialog.tmp"
        path.write_text("Welcome\r\n\rnetops@192.0.2.12's password: hunter2-secret\r\n")
        shown: list[str] = []
        echo = collector.DialogEcho(path, "R1", {"hunter2-secret"}, write=shown.append)
        echo.offset = 0
        echo._read(final=True)
        self.assertEqual(shown, ["R1| Welcome", f"R1| netops@192.0.2.12's password: {REDACTION_MARKER}"])

    def test_without_v_nothing_is_echoed(self):
        device = TranscriptDevice(dialog=self.DIALOG)
        with mock.patch.object(collector, "_echo_to_stdout", side_effect=AssertionError("echoed")):
            self.collect(device)

    def test_the_echo_goes_to_stdout_by_default(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            collector._echo_to_stdout("R1| pe-1#")
        self.assertEqual(out.getvalue(), "R1| pe-1#\n")


class TestTheServersAndTestbedCredentials(unittest.TestCase):
    TESTBED = textwrap.dedent("""\
        testbed:
          name: t
          credentials:
            default: {username: tbuser, password: tb-pass-1234}
          servers:
            jump:
              server: jump
              address: 192.0.2.1
              credentials:
                default: {username: ju, password: server-pass-4567}
            tftp:
              server: tftp
              address: 192.0.2.2
              password: bare-pass-7890
        devices:
          R1:
            os: iosxe
            credentials:
              default: {username: u, password: dev-pass-0000}
            connections:
              cli: {protocol: ssh, ip: 192.0.2.10}
        """)

    def test_the_secrets_of_servers_and_the_testbed_itself_are_scrubbed(self):
        servers = {
            "jump": {"credentials": {"default": {"password": "server-pass-4567"}}},
            "tftp": {"password": "bare-pass-7890"},
        }
        testbed = SimpleNamespace(
            credentials={"default": {"password": "tb-pass-1234"}}, servers=servers, devices={},
        )
        secrets = collector.testbed_secrets(testbed)
        self.assertEqual(secrets, {"tb-pass-1234", "server-pass-4567", "bare-pass-7890"})
        text = collector.redact_transcript("jump$ echo server-pass-4567 bare-pass-7890 tb-pass-1234", secrets)
        for secret in secrets:
            self.assertNotIn(secret, text)

    @unittest.skipUnless(HAVE_UNICON, "needs pyATS to load a testbed")
    def test_a_real_pyats_testbed_yields_them_all(self):
        import warnings

        from genie.testbed import load

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "testbed.yaml"
            path.write_text(self.TESTBED)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                testbed = load(str(path))
        self.assertEqual(
            collector.testbed_secrets(testbed),
            {"tb-pass-1234", "server-pass-4567", "bare-pass-7890", "dev-pass-0000"},
        )


# --------------------------------------------------------------------------
# A whole run: the policy, the prompt and the manifest
# --------------------------------------------------------------------------


class TestAWholeRun(unittest.TestCase):
    def setUp(self):
        import types

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.base = self.dir / "snapshots"
        self.testbed_path = self.dir / "testbed.yaml"
        self.testbed_path.write_text("devices: {}\n", encoding="utf-8")
        jump = SimpleNamespace(name="jump", os="linux", custom={}, credentials={},
                               connections={"cli": {"protocol": "ssh", "ip": "192.0.2.1"}})
        r1 = SimpleNamespace(name="R1", os="iosxe", custom={}, credentials={},
                             connections={"cli": {"protocol": "ssh", "ip": "192.0.2.10", "proxy": "jump"}})
        r2 = SimpleNamespace(name="R2", os="iosxe", custom={}, credentials={},
                             connections={"cli": {"protocol": "ssh", "ip": "192.0.2.11"}})
        self.testbed = SimpleNamespace(devices={"jump": jump, "R1": r1, "R2": r2})
        genie = types.ModuleType("genie")
        genie_testbed = types.ModuleType("genie.testbed")
        genie_testbed.load = lambda path: self.testbed
        patcher = mock.patch.dict(sys.modules, {"genie": genie, "genie.testbed": genie_testbed})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.calls: list[tuple[str, dict]] = []

    def collect_device(self, device, *args, **kwargs):
        self.calls.append((device.name, kwargs))
        result = collector.DeviceResult(name=device.name, os="iosxe", connected=True)
        result.commands.append(collector.CommandResult(command="show version", status="parsed"))
        return result

    def collect(self, **kwargs):
        with mock.patch.object(collector, "_collect_device", side_effect=self.collect_device), \
                mock.patch.object(collector, "record_snapshot"):
            return collector.run_collect(self.testbed_path, base_dir=self.base, workers=1, **kwargs)

    def test_every_session_spawned_here_is_held_to_the_pins_and_a_hop_is_not(self):
        manifest = self.collect()
        pins = hostkeys.known_hosts_path(self.testbed_path)
        prefix = hostkeys.policy_options(pins)

        self.assertEqual(self.testbed.devices["jump"].connections["cli"]["ssh_options"], prefix)
        self.assertEqual(self.testbed.devices["R2"].connections["cli"]["ssh_options"], prefix)
        self.assertNotIn("ssh_options", self.testbed.devices["R1"].connections["cli"])
        self.assertEqual(manifest["connection_policy"], {
            "allow_legacy_ssh": False, "allow_telnet": False,
            "host_keys": "strict", "known_hosts": str(pins),
        })
        for _name, kwargs in self.calls:
            self.assertEqual(kwargs["known_hosts"], pins)
            self.assertFalse(kwargs["allow_legacy_ssh"])
            self.assertFalse(kwargs["allow_telnet"])

    def test_the_flags_reach_every_device_and_the_manifest(self):
        manifest = self.collect(allow_legacy_ssh=True, allow_telnet=True)
        self.assertTrue(all(kw["allow_legacy_ssh"] and kw["allow_telnet"] for _n, kw in self.calls))
        self.assertTrue(manifest["connection_policy"]["allow_legacy_ssh"])
        self.assertTrue(manifest["connection_policy"]["allow_telnet"])

    def test_the_prompt_is_asked_about_the_jump_host_and_direct_devices_before_any_login(self):
        asked: list[str] = []

        def confirm(target, keys):
            asked.append(target.pattern)
            self.assertEqual(self.calls, [], "asked after a login started")
            return True

        with mock.patch.object(hostkeys, "scan", side_effect=lambda address, port: [
            hostkeys.ScannedKey(hostkeys.host_pattern(address, port), "ssh-ed25519", ED25519_LINE_KEY)
        ]):
            self.collect(confirm_host_key=confirm)

        self.assertEqual(sorted(asked), ["192.0.2.1", "192.0.2.11"])
        pins = hostkeys.known_hosts_path(self.testbed_path)
        self.assertTrue(hostkeys.is_pinned(pins, "192.0.2.1"))
        self.assertFalse(hostkeys.is_pinned(pins, "192.0.2.10"))

    def test_without_a_terminal_no_key_is_read_and_none_pinned(self):
        with mock.patch.object(hostkeys, "scan", side_effect=AssertionError("scanned")):
            self.collect()
        self.assertFalse(hostkeys.known_hosts_path(self.testbed_path).exists())


if __name__ == "__main__":
    unittest.main()
