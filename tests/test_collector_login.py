"""The login phase: jumphosts that ask questions before handing over a shell.

A router behind a jumphost is reached through one SSH session that spans both,
so the router's connect call is the only place a jumphost's questions can be
answered. These tests build testbed-shaped objects rather than importing pyATS,
so they run with no lab and no dependencies.
"""

from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path

from netstate import collector
from netstate.collector import (
    MAX_LOGIN_RESPONSE,
    REDACTION_MARKER,
    CommandPolicy,
    LoginPrompt,
    LoginPromptError,
    login_prompts,
    proxy_names,
)
from tests.test_collector_enable import OwnTempDirectoryTestCase

WARNING_PATTERN = r"continue\s*\[Yes/No\]\s*\?\s*:\s*$"


class FakeDevice:
    """A testbed device as pyATS presents one: attributes, dict-like members."""

    def __init__(self, name, connections=None, custom=None, credentials=None):
        self.name = name
        self.connections = connections or {}
        self.custom = custom or {}
        self.credentials = credentials or {}
        self.testbed = None


class FakeTestbed:
    def __init__(self, *devices):
        self.devices = {device.name: device for device in devices}
        for device in devices:
            device.testbed = self


def jumphost(prompts=None, credentials=None):
    return FakeDevice(
        "jumphost",
        connections={"cli": {"protocol": "ssh", "ip": "192.0.2.10"}},
        custom={"login_prompts": prompts} if prompts is not None else {},
        credentials=credentials or {},
    )


def router(name="rbt-ald-pe1", proxy="jumphost", custom=None):
    connection = {"protocol": "ssh", "ip": "198.51.100.1"}
    if proxy is not None:
        connection["proxy"] = [{"device": proxy, "command": " ssh 198.51.100.1 netops"}]
    return FakeDevice(name, connections={"cli": connection}, custom=custom or {})


class ProxyDiscoveryTestCase(unittest.TestCase):
    def test_a_router_reports_the_jumphost_it_is_reached_through(self):
        self.assertEqual(proxy_names(router()), ("jumphost",))

    def test_a_proxy_written_as_a_bare_name_is_read_the_same_way(self):
        device = FakeDevice("R1", connections={"cli": {"proxy": "jumphost"}})
        self.assertEqual(proxy_names(device), ("jumphost",))

    def test_a_router_with_no_proxy_reports_none(self):
        self.assertEqual(proxy_names(router(proxy=None)), ())

    def test_a_device_with_no_connections_at_all_does_not_raise(self):
        self.assertEqual(proxy_names(FakeDevice("R1")), ())


class LoginPromptTestCase(unittest.TestCase):
    def test_a_prompt_declared_on_the_jumphost_is_answered_by_the_router(self):
        # The whole point: the question belongs to the jumphost, but the
        # session that meets it is opened against the router.
        testbed = FakeTestbed(
            jumphost([{"pattern": WARNING_PATTERN, "response": "Yes"}]), router()
        )
        prompts = login_prompts(testbed.devices["rbt-ald-pe1"], testbed)
        self.assertEqual(prompts, (LoginPrompt(WARNING_PATTERN, "Yes", "jumphost"),))

    def test_a_router_declaring_its_own_prompt_keeps_it(self):
        testbed = FakeTestbed(
            router(custom={"login_prompts": [{"pattern": "yes/no", "response": "yes"}]}),
        )
        prompts = login_prompts(testbed.devices["rbt-ald-pe1"], testbed)
        self.assertEqual([prompt.response for prompt in prompts], ["yes"])

    def test_the_same_prompt_on_both_ends_is_answered_once(self):
        entry = [{"pattern": WARNING_PATTERN, "response": "Yes"}]
        testbed = FakeTestbed(jumphost(entry), router(custom={"login_prompts": entry}))
        self.assertEqual(len(login_prompts(testbed.devices["rbt-ald-pe1"], testbed)), 1)

    def test_a_device_with_nothing_declared_has_no_prompts(self):
        testbed = FakeTestbed(jumphost(), router())
        self.assertEqual(login_prompts(testbed.devices["rbt-ald-pe1"], testbed), ())

    def test_a_proxy_missing_from_the_testbed_warns_rather_than_failing(self):
        testbed = FakeTestbed(router(proxy="not-here"))
        with self.assertLogs("netstate.collector", level=logging.WARNING) as logged:
            self.assertEqual(login_prompts(testbed.devices["rbt-ald-pe1"], testbed), ())
        self.assertIn("not-here", "\n".join(logged.output))


class LoginPromptValidationTestCase(unittest.TestCase):
    """A login answer is typed before any prompt exists, so the allowlist
    cannot see it. These are the bounds that stand in its place."""

    def prompts_for(self, entry):
        testbed = FakeTestbed(jumphost([entry]), router())
        return login_prompts(testbed.devices["rbt-ald-pe1"], testbed)

    def test_a_configuration_verb_is_refused_before_the_run_starts(self):
        with self.assertRaises(LoginPromptError) as raised:
            self.prompts_for({"pattern": "#", "response": "configure terminal"})
        self.assertIn("read-only", str(raised.exception))

    def test_a_response_carrying_a_second_line_is_refused(self):
        with self.assertRaises(LoginPromptError) as raised:
            self.prompts_for({"pattern": "#", "response": "Yes\nconfigure terminal"})
        self.assertIn("single line", str(raised.exception))

    def test_a_control_character_in_a_response_is_refused(self):
        """BUG-249: ^U erases the answer typed before it, and what follows it is typed as a command."""
        for response in ("Yes\x15write memory", "Yes\x17reload", "Yes\x1b", "Y\u00e9s"):
            with self.subTest(response=response):
                with self.assertRaises(LoginPromptError) as raised:
                    self.prompts_for({"pattern": "#", "response": response})
                self.assertIn("printable", str(raised.exception))

    def test_a_configuration_verb_anywhere_in_a_response_is_refused(self):
        """BUG-249: only the first word was read, so 'Yes write memory' was accepted."""
        for response in ("Yes write memory", "y reload", "ok then configure terminal"):
            with self.subTest(response=response):
                with self.assertRaises(LoginPromptError) as raised:
                    self.prompts_for({"pattern": "#", "response": response})
                self.assertIn("read-only", str(raised.exception))

    def test_an_abbreviated_configuration_verb_is_refused(self):
        """BUG-317: a CLI takes any unambiguous start of a verb, so 'wri' is 'write'."""
        for response in ("wri", "rel", "Yes conf t", "del", "era", "WRIT mem", "rollb"):
            with self.subTest(response=response):
                with self.assertRaises(LoginPromptError) as raised:
                    self.prompts_for({"pattern": "#", "response": response})
                self.assertIn("read-only", str(raised.exception))

    def test_an_ordinary_answer_is_still_accepted(self):
        for response in ("Yes", "y", "I accept", "", "Passw0rd!#"):
            with self.subTest(response=response):
                self.assertEqual(self.prompts_for({"pattern": "#", "response": response})[0].response, response)

    def test_a_response_longer_than_an_answer_is_refused(self):
        with self.assertRaises(LoginPromptError):
            self.prompts_for({"pattern": "#", "response": "y" * (MAX_LOGIN_RESPONSE + 1)})

    def test_a_pattern_that_is_not_a_regex_is_refused(self):
        with self.assertRaises(LoginPromptError) as raised:
            self.prompts_for({"pattern": "continue [Yes/No", "response": "Yes"})
        self.assertIn("valid regex", str(raised.exception))

    def test_a_missing_response_is_refused(self):
        with self.assertRaises(LoginPromptError):
            self.prompts_for({"pattern": "continue"})

    def test_a_list_of_strings_instead_of_pairs_is_refused(self):
        testbed = FakeTestbed(jumphost(["Yes"]), router())
        with self.assertRaises(LoginPromptError):
            login_prompts(testbed.devices["rbt-ald-pe1"], testbed)

    def test_the_error_names_the_device_and_the_entry(self):
        with self.assertRaises(LoginPromptError) as raised:
            self.prompts_for({"pattern": "#", "response": "reload"})
        self.assertIn("jumphost: custom.login_prompts[1]", str(raised.exception))


class ConnectingDevice:
    """Enough of a Genie device to watch what `connect` is called with."""

    class Settings:
        EXEC_TIMEOUT = 0

    class Default:
        def __init__(self):
            self.settings = ConnectingDevice.Settings()

    def __init__(self, name="R1"):
        self.name = name
        self.os = "iosxe"
        self.default = self.Default()
        self.connect_kwargs = None
        self.order: list[str] = []

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        self.order.append("connect")

    def disconnect(self):
        self.order.append("disconnect")

    def execute(self, command, timeout=None):
        return f"<output of {command}>"

    def parse(self, command, output=None):
        return {"ok": True}


class RecordingGate:
    """A stand-in for the per-jumphost lock that records when it is held."""

    def __init__(self, order):
        self.order = order

    def __enter__(self):
        self.order.append("gate-acquired")
        return self

    def __exit__(self, *exc):
        self.order.append("gate-released")
        return False


class ConnectArgumentsTestCase(OwnTempDirectoryTestCase):
    """What reaches `device.connect` decides whether a login can answer."""

    POLICY = CommandPolicy({"iosxe": {"parse": ["show version"]}})

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        # The dialog itself is unicon's; building one needs unicon installed,
        # and these tests are offline. What is under test is the wiring.
        self._dialog = collector.login_dialog
        collector.login_dialog = lambda prompts: "<dialog>" if tuple(prompts) else None

    def tearDown(self):
        collector.login_dialog = self._dialog
        self._tmp.cleanup()

    def collect(self, device, prompts=(), gate=None):
        return collector._collect_device(
            device, self.POLICY, self.root, prompts=prompts, login_gate=gate
        )

    def test_a_device_with_declared_prompts_connects_with_a_dialog(self):
        device = ConnectingDevice()
        self.collect(device, (LoginPrompt(WARNING_PATTERN, "Yes", "jumphost"),))
        self.assertEqual(device.connect_kwargs["connect_reply"], "<dialog>")

    def test_a_device_with_no_prompts_connects_exactly_as_it_always_did(self):
        # No `connect_reply` at all rather than None: a lab with no jumphost
        # must not start taking a different code path through unicon.
        device = ConnectingDevice()
        self.collect(device)
        self.assertNotIn("connect_reply", device.connect_kwargs)

    def test_the_read_only_connect_arguments_are_unchanged_by_any_of_this(self):
        device = ConnectingDevice()
        self.collect(device, (LoginPrompt(WARNING_PATTERN, "Yes", "jumphost"),))
        self.assertEqual(device.connect_kwargs["init_config_commands"], [])
        self.assertTrue(device.connect_kwargs["learn_hostname"])

    def test_a_login_through_a_jumphost_still_keeps_unicon_from_asking_anything_itself(self):
        device = ConnectingDevice()
        self.collect(device, (LoginPrompt(WARNING_PATTERN, "Yes", "jumphost"),))
        self.assertEqual(device.connect_kwargs["connect_reply"], "<dialog>")
        self.assertIs(device.connect_kwargs["operating_mode"], True)
        self.assertIs(device.connect_kwargs["learn_os_version"], False)

    def test_a_login_through_a_jumphost_is_taken_inside_the_gate(self):
        # Two nested ssh dialogs racing on one jumphost interleave their
        # output, and the second is answering questions it cannot see whole.
        device = ConnectingDevice()
        gate = RecordingGate(device.order)
        self.collect(device, gate=gate)
        self.assertEqual(device.order[:3], ["gate-acquired", "connect", "gate-released"])

    def test_the_gate_is_released_before_the_commands_run(self):
        device = ConnectingDevice()
        gate = RecordingGate(device.order)
        outcome = self.collect(device, gate=gate)
        self.assertTrue(outcome.connected)
        self.assertNotIn("gate-acquired", device.order[3:])


class SecretString(str):
    """A pyATS Secret as far as this matters: it hides itself when printed."""

    def __new__(cls, plaintext):
        secret = super().__new__(cls, "****")
        secret.plaintext = plaintext
        return secret


class SessionTranscriptTestCase(OwnTempDirectoryTestCase):
    """The transcript is the one stream that would otherwise carry a password."""

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_every_credential_in_the_testbed_is_collected_including_the_jumphost(self):
        # The jumphost is never collected from, but its password is the one
        # typed in the clear during a proxied login.
        testbed = FakeTestbed(
            jumphost(credentials={"default": {"username": "admin", "password": "Hop!Pass77"}}),
            router(),
        )
        self.assertEqual(collector.testbed_secrets(testbed), {"Hop!Pass77"})

    def test_a_secret_that_will_not_give_up_its_plaintext_is_not_searched_for(self):
        testbed = FakeTestbed(jumphost(credentials={"default": {"password": "****"}}))
        self.assertEqual(collector.testbed_secrets(testbed), set())

    def test_a_pyats_secret_object_yields_the_literal_that_gets_typed(self):
        testbed = FakeTestbed(
            jumphost(credentials={"default": {"password": SecretString("Hop!Pass77")}})
        )
        self.assertEqual(collector.testbed_secrets(testbed), {"Hop!Pass77"})

    def test_a_login_prompt_s_answer_is_collected_too(self):
        """C4-07: the answer is kept out of collect.log as a possible password, and was left in connect.log.

        A jump host that echoes what it is told (an access-code banner, a
        shell `read`) wrote the answer into the transcript in clear. An
        answer shorter than four characters (`Yes`, `y`) is not searched for,
        as a password of that length is not.
        """
        testbed = FakeTestbed(
            jumphost(prompts=[{"pattern": r"Access code:\s*$", "response": "Kq7ZA9xP4m"},
                              {"pattern": r"continue\s*\[Yes/No\]", "response": "Yes"}],
                     credentials={"default": {"username": "ops", "password": "Hop!Pass77"}}),
            router(custom={"login_prompts": [{"pattern": r"PIN:\s*$", "response": "4711"}]}),
        )
        self.assertEqual(collector.testbed_secrets(testbed), {"Hop!Pass77", "Kq7ZA9xP4m", "4711"})
        transcript = self.root / "rbt-ald-pe1" / collector.CONNECT_LOG_TEMP
        transcript.parent.mkdir(parents=True)
        transcript.write_text("ops@jumphost's password: \nAccess code: Kq7ZA9xP4m\nrbt-ald-pe1#\n", encoding="utf-8")
        kept = collector.store_connect_log(ConnectingDevice("rbt-ald-pe1"), self.root, collector.testbed_secrets(testbed))
        self.assertNotIn("Kq7ZA9xP4m", (self.root / kept).read_text(encoding="utf-8"))

    def test_a_malformed_login_prompt_entry_does_not_stop_the_collection_of_secrets(self):
        testbed = FakeTestbed(jumphost(prompts=[{"pattern": "(", "response": "Kq7ZA9xP4m"}, "junk", {"response": 12345}]))
        self.assertEqual(collector.testbed_secrets(testbed), {"Kq7ZA9xP4m"})

    def write(self, secrets, *messages):
        """session.log as a run writes it: from the transcript unicon left, redacted whole."""
        transcript = self.root / "R1" / collector.CONNECT_LOG_TEMP
        transcript.parent.mkdir(parents=True)
        transcript.write_text("\n".join(messages) + "\n", encoding="utf-8")
        kept = collector.store_connect_log(ConnectingDevice("R1"), self.root, secrets)
        collector.write_session_log(self.root, [collector.DeviceResult(name="R1", connect_log=kept)])
        return (self.root / "session.log").read_text(encoding="utf-8")

    def test_a_password_echoed_by_the_jumphost_does_not_reach_the_file(self):
        written = self.write({"Hop!Pass77"}, "netops@192.0.2.10's password: Hop!Pass77")
        self.assertNotIn("Hop!Pass77", written)
        self.assertIn(REDACTION_MARKER, written)

    def test_a_longer_secret_containing_a_shorter_one_is_masked_whole(self):
        written = self.write({"Labnet!", "Hop!Pass77"}, "typed Hop!Pass77 at the prompt")
        self.assertNotIn("Pass77", written)

    def test_the_line_redaction_that_guards_raw_files_runs_here_too(self):
        # A secret nobody declared in the testbed still must not land on disk.
        written = self.write(set(), "snmp-server community s3cr3t RO")
        self.assertNotIn("s3cr3t", written)

    def test_the_dialog_itself_survives_so_the_transcript_is_worth_reading(self):
        written = self.write(set(), "Are you sure you want to continue [Yes/No] ? :")
        self.assertIn("[Yes/No]", written)


class TranscriptDevice(ConnectingDevice):
    """A device whose connect writes unicon's transcript where it was told to."""

    DIALOG = "admin@10.0.0.1's password: Hop!Pass77\nR1#\nR1# show running-config\n"

    def __init__(self, name="R1", fail=False):
        super().__init__(name)
        self.fail = fail

    def connect(self, **kwargs):
        super().connect(**kwargs)
        Path(kwargs["logfile"]).write_text(self.DIALOG, encoding="utf-8")
        if self.fail:
            raise RuntimeError("failed to connect to R1")


class ConnectLogTestCase(OwnTempDirectoryTestCase):
    """unicon's transcript never outlives the session in the clear (review A1)."""

    POLICY = CommandPolicy({"iosxe": {"parse": ["show version"]}})

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def collect(self, device):
        return collector._collect_device(
            device, self.POLICY, self.root, secrets={"Hop!Pass77"}
        )

    def test_the_transcript_is_asked_for_inside_the_snapshot(self):
        device = TranscriptDevice()
        self.collect(device)
        self.assertEqual(
            Path(device.connect_kwargs["logfile"]), self.root / "R1" / collector.CONNECT_LOG_TEMP
        )

    def test_after_the_session_only_a_redacted_copy_remains_and_the_manifest_names_it(self):
        outcome = self.collect(TranscriptDevice())
        self.assertEqual(outcome.connect_log, "R1/connect.log")
        kept = (self.root / "R1" / "connect.log").read_text(encoding="utf-8")
        self.assertNotIn("Hop!Pass77", kept)
        self.assertIn("R1# show running-config", kept)
        self.assertFalse((self.root / "R1" / collector.CONNECT_LOG_TEMP).exists())

    def test_a_failed_login_keeps_its_redacted_transcript_too(self):
        outcome = self.collect(TranscriptDevice(fail=True))
        self.assertFalse(outcome.connected)
        self.assertEqual(outcome.connect_log, "R1/connect.log")
        self.assertNotIn("Hop!Pass77", (self.root / "R1" / "connect.log").read_text())
        self.assertFalse((self.root / "R1" / collector.CONNECT_LOG_TEMP).exists())

    def test_a_transcript_whose_redacted_copy_cannot_be_written_is_still_removed(self):
        """BUG-343: a failed write of the redacted copy skipped the delete, so the clear one stayed."""
        transcript = self.root / "R1" / collector.CONNECT_LOG_TEMP
        transcript.parent.mkdir(parents=True)
        transcript.write_text(TranscriptDevice.DIALOG, encoding="utf-8")
        # A directory where the redacted copy goes: writing it fails.
        (self.root / "R1" / collector.CONNECT_LOG_NAME).mkdir()
        with self.assertLogs("netstate", level="WARNING") as logged:
            kept = collector.store_connect_log(ConnectingDevice("R1"), self.root, {"Hop!Pass77"})
        self.assertIsNone(kept)
        self.assertFalse(transcript.exists())
        self.assertIn("could not keep the session transcript", "\n".join(logged.output))

    def test_a_device_that_never_connected_records_no_transcript(self):
        device = ConnectingDevice()
        device.os = ""
        outcome = self.collect(device)
        self.assertIsNone(outcome.connect_log)

    def test_a_unicon_log_in_the_real_temp_directory_is_neither_read_nor_deleted(self):
        # Named so that it can only be this test's own file. Its XR prompt
        # would read as a wrong `os:` if the collection took it for the fake's
        # dialog, and the collection would then delete it.
        dialog = "RP/0/RP0/CPU0:DN-ISOLATION-R1#\n"
        planted = self.real_tempdir / "DN-ISOLATION-R1-cli-20260929T000000.log"
        planted.write_text(dialog, encoding="utf-8")
        self.addCleanup(planted.unlink, missing_ok=True)

        outcome = self.collect(ConnectingDevice("DN-ISOLATION-R1"))

        self.assertTrue(outcome.connected)
        self.assertIsNone(outcome.detected_os)
        self.assertIsNone(outcome.connect_log)
        self.assertEqual(planted.read_text(encoding="utf-8"), dialog)

    def test_a_log_in_the_temp_directory_is_another_sessions_and_is_left_alone(self):
        """BUG-252: this run's transcript is where the connect was told to write it.

        A device that cannot say where its log went was looked up by name in
        the temp directory, where this run never writes: what was found there
        was another session's, or another device's whose name starts with this
        one's, read as this device's dialog and then deleted.
        """
        dialog = "RP/0/RP0/CPU0:R1#\n"
        planted = [
            self.tempdir / "R1-cli-20261010T100000000.log",
            self.tempdir / "R1-core-cli-20261010T100000000.log",
        ]
        for path in planted:
            path.write_text(dialog, encoding="utf-8")

        outcome = self.collect(ConnectingDevice("R1"))

        self.assertTrue(outcome.connected)
        self.assertIsNone(outcome.detected_os)
        self.assertIsNone(outcome.connect_log)
        for path in planted:
            self.assertEqual(path.read_text(encoding="utf-8"), dialog)

    def test_the_next_run_cleans_up_what_a_crashed_run_left_in_the_clear(self):
        base = self.root / "snapshots"
        leftover = base / "20260901T090000Z" / "DN-SWEEP-R1" / collector.CONNECT_LOG_TEMP
        leftover.parent.mkdir(parents=True)
        leftover.write_text("password: Hop!Pass77\nDN-SWEEP-R1#\n", encoding="utf-8")
        stray = self.tempdir / "DN-SWEEP-R1-cli-20260901T090000.log"
        stray.write_text("password: Hop!Pass77\n", encoding="utf-8")
        self.addCleanup(lambda: stray.unlink(missing_ok=True))
        handled = collector.sweep_connect_logs(base, ["DN-SWEEP-R1"], {"Hop!Pass77"})
        self.assertEqual(handled, 2)
        self.assertFalse(leftover.exists())
        self.assertFalse(stray.exists())
        redacted = leftover.with_name("connect.log").read_text(encoding="utf-8")
        self.assertNotIn("Hop!Pass77", redacted)
        self.assertIn("DN-SWEEP-R1#", redacted)


class DebugLinesInATranscript(unittest.TestCase):
    """BUG-056: unicon's DEBUG lines are repr copies, so they leave the transcript whole."""

    DIALOG = (
        "2026-10-10 10:00:00,000: %UNICON-INFO: connection to R1\n"
        "2026-10-10 10:00:01,000: %UNICON-DEBUG: buffer: 'R1#show running-config\\r\\n"
        "snmp-server community s3cr3t RO\\r\\nR1#'\n"
        "snmp-server community s3cr3t RO\n"
        "R1#\n"
    )

    def test_a_secret_inside_a_repr_buffer_does_not_survive(self):
        kept = collector.redact_transcript(self.DIALOG)
        self.assertNotIn("s3cr3t", kept)
        self.assertNotIn("%UNICON-DEBUG", kept)

    def test_the_dialog_around_the_debug_lines_is_kept(self):
        kept = collector.redact_transcript(self.DIALOG)
        self.assertIn("%UNICON-INFO: connection to R1", kept)
        self.assertIn("R1#", kept)

    def test_a_typed_secret_is_masked_in_its_repr_escaped_spelling_too(self):
        secret = "Hop\\Pass'77"
        kept = collector.redact_transcript("sent: 'Hop\\\\Pass\\'77\\r'\n", {secret})
        self.assertNotIn("Pass", kept)


if __name__ == "__main__":
    unittest.main()
