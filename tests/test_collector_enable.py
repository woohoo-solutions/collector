"""The second enable some IOS-XE deployments demand after login.

Such a device authenticates all the way to `hostname#` and is still not
privileged: it wants `enable` again, and a password. That has to happen before
the session's terminal settings, because an unprivileged session refuses those
too — and unicon reports the refusal as "failed to connect", which reads as an
unreachable device.

All of it is exercised against a recording device; unicon is never imported.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from netstate import collector
from netstate.platforms import platform_for
from netstate.collector import (
    CommandPolicy,
    _collect_device,
    connect_failure_hint,
    enable_secret,
    wants_double_enable,
)

POLICY = CommandPolicy({"iosxe": {"parse": ["show version"]}})

DIALOG = object()  # stands in for the unicon Dialog, which is never built here


class FakeSecret:
    """Stands in for a pyATS SecretString: str() hides it, .plaintext is it."""

    def __init__(self, plaintext: str):
        self.plaintext = plaintext

    def __str__(self) -> str:
        return "%ENC{Ejcpigo...}"


class RecordingDevice:
    """A device that records what was sent to it, in order.

    It keeps a connection object the way pyATS does, checked against unicon's
    own mock device: the plugin is chosen from `os` when the object is built,
    `disconnect()` keeps the object and `destroy()` drops it. Each login
    appends its dialog to one transcript, as unicon does with a rebuilt
    connection's logfile.
    """

    def __init__(
        self, custom=None, testbed=None, credentials=None, connections=None, fail_once=(),
        os_name="iosxe", outputs=None, dialogs=(), connect_errors=(),
    ):
        self.name = "emo_mce_1"
        self.os = os_name
        self.platform = os_name
        self.outputs = dict(outputs or {})
        self.custom = dict(custom or {})
        self.testbed = testbed
        self.credentials = (
            {"enable": {"password": "enable-secret"}} if credentials is None else credentials
        )
        self.connections = dict(connections or {})
        self.connect_kwargs: list[dict] = []
        self.sent: list[tuple[str, object]] = []
        self.execute_kwargs: list[dict] = []
        self.default = SimpleNamespace(settings=SimpleNamespace(EXEC_TIMEOUT=60))
        self.connect_error: Exception | None = None
        self.fail_once = set(fail_once)
        self.plugins: list[str] = []  # the OS each connection object was built for
        self._built = False
        self.dialogs = list(dialogs)  # what each login writes, in order
        self.connect_errors = list(connect_errors)  # per login, None to succeed
        self.destroy_error: Exception | None = None

    def connect(self, **kwargs):
        self.connect_kwargs.append(kwargs)
        self.sent.append(("<connect>", None))
        if not self._built:
            self.plugins.append(self.os)
            self._built = True
        if self.dialogs:
            with open(self.default._logfile, "a", encoding="utf-8") as handle:
                handle.write(self.dialogs.pop(0))
        error = self.connect_errors.pop(0) if self.connect_errors else None
        if error or self.connect_error:
            raise error or self.connect_error

    def destroy(self):
        self.sent.append(("<destroy>", None))
        if self.destroy_error:
            raise self.destroy_error
        self._built = False

    # **kwargs mirrors the real unicon execute service, which takes them and
    # ignores what it does not know. A fake with a narrower signature would
    # turn an extra argument into a TypeError the real device never raises.
    def execute(self, command, timeout=None, reply=None, **kwargs):
        self.sent.append((command, reply))
        self.execute_kwargs.append((command, kwargs))
        if command in self.fail_once:
            self.fail_once.discard(command)
            raise TimeoutError(f"timeout occurred: timeout value: {timeout}")
        return self.outputs.get(command, f"<output of {command}>")

    def parse(self, command, output=None):
        return {"command": command}

    def disconnect(self):
        pass

    @property
    def commands(self) -> list[str]:
        return [command for command, _reply in self.sent]


class OwnTempDirectoryTestCase(unittest.TestCase):
    """A temp directory of the test's own, where unicon's would be.

    A connect that names no transcript of its own is looked for as unicon's
    default log, `<tempdir>/<device>-<via>-<stamp>.log`; the newest one is
    read as that device's dialog. In a test the fake names no log, so the
    one it found would be a real session's from the last hour. A collection
    and the wizard's login check each ask for a file of their own and never
    look there (BUG-252, BUG-176), but every test that logs in through such
    a fake runs against this directory all the same, so one that did look
    would read and delete nothing real.
    `real_tempdir` is the one it stands in for, so a test can prove nothing
    there was touched.
    """

    def setUp(self):
        super().setUp()
        self.real_tempdir = Path(tempfile.gettempdir())
        own = tempfile.TemporaryDirectory()
        self.addCleanup(own.cleanup)
        self.tempdir = Path(own.name)
        patcher = mock.patch.object(collector.tempfile, "gettempdir", new=lambda: own.name)
        patcher.start()
        self.addCleanup(patcher.stop)


class DoubleEnableTestCase(OwnTempDirectoryTestCase):
    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        # The real dialog needs unicon; the tests only care that one was built
        # from the right secret and handed to the right command.
        self._real_dialog = collector._enable_dialog
        self.dialog_secrets: list[str] = []

        def fake_dialog(password):
            self.dialog_secrets.append(password)
            return DIALOG

        collector._enable_dialog = fake_dialog

    def tearDown(self):
        collector._enable_dialog = self._real_dialog
        self._tmp.cleanup()

    def collect(self, device, **kwargs):
        return _collect_device(device, POLICY, self.root, **kwargs)


class TestWhenTheSecondEnableIsSent(unittest.TestCase):
    def test_a_device_asks_for_it_through_its_own_custom_block(self):
        self.assertTrue(wants_double_enable(RecordingDevice(custom={"double_enable": True})))

    def test_a_whole_lab_can_ask_for_it_once_on_the_testbed(self):
        testbed = SimpleNamespace(custom={"double_enable": True})
        self.assertTrue(wants_double_enable(RecordingDevice(testbed=testbed)))

    def test_a_device_overrides_the_testbed_in_either_direction(self):
        testbed = SimpleNamespace(custom={"double_enable": True})
        device = RecordingDevice(custom={"double_enable": False}, testbed=testbed)
        self.assertFalse(wants_double_enable(device))

        testbed = SimpleNamespace(custom={"double_enable": False})
        device = RecordingDevice(custom={"double_enable": True}, testbed=testbed)
        self.assertTrue(wants_double_enable(device))

    def test_nothing_declared_means_no_second_enable(self):
        self.assertFalse(wants_double_enable(RecordingDevice()))
        self.assertFalse(wants_double_enable(RecordingDevice(testbed=SimpleNamespace())))


class TestTheSecretItAnswersWith(unittest.TestCase):
    def test_the_enable_credential_is_preferred(self):
        device = RecordingDevice(
            credentials={
                "default": {"username": "u", "password": "login-secret"},
                "enable": {"password": "enable-secret"},
            }
        )
        self.assertEqual(enable_secret(device), "enable-secret")

    def test_the_login_password_is_used_when_no_enable_credential_exists(self):
        # These devices take the same secret twice, so a testbed that declares
        # only the default credential is not a misconfiguration.
        device = RecordingDevice(credentials={"default": {"password": "login-secret"}})
        self.assertEqual(enable_secret(device), "login-secret")

    def test_an_encoded_password_is_decoded_rather_than_sent_as_its_markup(self):
        device = RecordingDevice(credentials={"enable": {"password": FakeSecret("real")}})
        self.assertEqual(enable_secret(device), "real")

    def test_no_credentials_at_all_yields_nothing(self):
        self.assertEqual(enable_secret(RecordingDevice(credentials={})), "")
        self.assertEqual(enable_secret(RecordingDevice(credentials={"enable": {}})), "")


class TestTheConnectSequence(DoubleEnableTestCase):
    def test_the_enable_precedes_the_terminal_settings(self):
        """The ordering is the fix: an unprivileged session refuses them.

        The `show version` ahead of the enable is the identification: it names
        no other platform here, so the enable goes ahead.
        """
        device = RecordingDevice(custom={"double_enable": True})
        outcome = self.collect(device)

        self.assertTrue(outcome.connected)
        self.assertEqual(
            device.commands,
            [
                "<connect>", "show version", "enable", "terminal length 0",
                "terminal width 0", "show version",
            ],
        )

    def test_the_connect_itself_sends_nothing(self):
        # unicon runs init_exec_commands as the last step of the connect, which
        # is before the enable — so on these devices the list must be empty and
        # the same commands sent by hand afterwards.
        device = RecordingDevice(custom={"double_enable": True})
        self.collect(device)

        self.assertEqual(device.connect_kwargs[0]["init_exec_commands"], [])
        self.assertEqual(device.connect_kwargs[0]["init_config_commands"], [])

    def test_the_password_prompt_is_answered_by_a_dialog_on_that_command(self):
        device = RecordingDevice(custom={"double_enable": True})
        self.collect(device)

        self.assertEqual(self.dialog_secrets, ["enable-secret"])
        self.assertEqual(dict(device.sent)["enable"], DIALOG)
        # Nothing else is given a dialog to reply with.
        self.assertEqual(
            [command for command, reply in device.sent if reply is not None], ["enable"]
        )

    def test_unicon_is_told_to_expect_the_privilege_transition(self):
        # `enable` moves the state machine. unicon's execute service objects to
        # a command that does that unless it is told to expect it, even where
        # the prompt does not visibly change.
        device = RecordingDevice(custom={"double_enable": True})
        self.collect(device)

        sent_with = dict(device.execute_kwargs)
        self.assertTrue(sent_with["enable"]["allow_state_change"])
        self.assertNotIn("allow_state_change", sent_with["terminal length 0"])

    def test_unicon_is_told_not_to_ask_the_device_anything_itself(self):
        # Left alone, unicon's IOS-XE plugin sends `show version | include
        # operating mode` and `show install summary` on every connect, and
        # `pnpa service discovery stop` to a controller-managed device.
        for device in (RecordingDevice(), RecordingDevice(custom={"double_enable": True})):
            self.collect(device)
            self.assertIs(device.connect_kwargs[0]["operating_mode"], True)
            self.assertIs(device.connect_kwargs[0]["learn_os_version"], False)

    def test_an_ordinary_device_is_untouched_by_any_of_this(self):
        device = RecordingDevice()
        self.collect(device)

        self.assertEqual(device.connect_kwargs[0]["init_exec_commands"], list(platform_for("iosxe").session_setup))
        # One `show version` to settle what a bare `hostname#` left open, kept
        # as the collection's own (BUG-344); no enable, no second session.
        self.assertEqual(device.commands, ["<connect>", "show version"])
        self.assertEqual(self.dialog_secrets, [])

    def test_the_command_line_can_force_it_on_for_a_lab_that_declares_nothing(self):
        device = RecordingDevice()
        self.collect(device, double_enable=True)

        self.assertIn("enable", device.commands)
        self.assertLess(device.commands.index("enable"), device.commands.index("terminal length 0"))

    def test_the_command_sent_can_only_ever_be_the_bare_enable(self):
        # It comes from a module constant, so no testbed value can reach it.
        device = RecordingDevice(custom={"double_enable": "yes please"})
        self.collect(device)

        unprivileged = [
            command for command in device.commands
            if not command.startswith(("show ", "terminal ", "<"))
        ]
        self.assertEqual(unprivileged, ["enable"])

    def test_a_testbed_with_no_password_says_so_instead_of_sending_a_blank_one(self):
        device = RecordingDevice(custom={"double_enable": True}, credentials={})
        outcome = self.collect(device)

        self.assertFalse(outcome.connected)
        self.assertIn("no enable or default password", outcome.error)
        self.assertNotIn("enable", device.commands)


XR_POLICY = CommandPolicy({
    "iosxe": {"parse": ["show version"]},
    "iosxr": {"parse": ["show version"]},
})

XR_VERSION = "Cisco IOS XR Software, Version 7.5.2\nncs-540 () processor\n"


class TestAPlatformWithNoEnableStep(DoubleEnableTestCase):
    """IOS-XR has no enable. On an NCS540 the word reaches PAM and the session hangs."""

    def test_an_ios_xr_device_is_never_sent_an_enable_even_when_the_command_line_asks(self):
        device = RecordingDevice(os_name="iosxr")
        outcome = _collect_device(device, XR_POLICY, self.root, double_enable=True)

        self.assertTrue(outcome.connected)
        self.assertNotIn("enable", device.commands)
        self.assertEqual(
            device.connect_kwargs[0]["init_exec_commands"],
            list(platform_for("iosxr").session_setup),
        )

    def test_a_testbed_wide_double_enable_does_not_reach_an_ios_xr_device(self):
        testbed = SimpleNamespace(custom={"double_enable": True})
        device = RecordingDevice(os_name="iosxr", testbed=testbed)
        outcome = _collect_device(device, XR_POLICY, self.root)

        self.assertTrue(outcome.connected)
        self.assertNotIn("enable", device.commands)
        self.assertEqual(self.dialog_secrets, [])


class TestTheDeviceIsIdentifiedBeforeTheEnable(DoubleEnableTestCase):
    """A double-enable device declared as IOS-XE may be an XR box nobody has identified yet."""

    def test_an_xr_box_declared_as_ios_xe_is_identified_by_its_prompt_before_any_enable(self):
        log_file = self.root / "dialog.log"
        log_file.write_text("RP/0/RP0/CPU0:pe-1#\n", encoding="utf-8")
        device = RecordingDevice(custom={"double_enable": True})
        device.default._logfile = str(log_file)
        outcome = _collect_device(device, XR_POLICY, self.root)

        # The first session sends nothing at all: the prompt settles it. The
        # policy has an XR allowlist, so the device is logged into again as
        # XR and collected rather than reported and lost.
        self.assertEqual(device.commands, ["<connect>", "<destroy>", "<connect>", "show version"])
        self.assertTrue(outcome.connected)
        self.assertEqual(outcome.detected_os, "iosxr")
        self.assertEqual(outcome.os, "iosxr")

    def test_an_xr_box_whose_prompt_proves_nothing_is_identified_by_show_version(self):
        device = RecordingDevice(
            custom={"double_enable": True}, outputs={"show version": XR_VERSION}
        )
        outcome = _collect_device(device, XR_POLICY, self.root)

        self.assertEqual(device.commands[:2], ["<connect>", "show version"])
        self.assertTrue(outcome.connected)
        self.assertEqual(outcome.detected_os, "iosxr")
        self.assertEqual(outcome.os, "iosxr")
        self.assertEqual(self.dialog_secrets, [])

    def test_a_device_that_answers_as_ios_xe_is_enabled_as_before(self):
        device = RecordingDevice(
            custom={"double_enable": True},
            outputs={"show version": "Cisco IOS XE Software, Version 17.09.04a\n"},
        )
        outcome = _collect_device(device, XR_POLICY, self.root)

        self.assertTrue(outcome.connected)
        self.assertIn("enable", device.commands)

    def test_a_platform_that_has_an_enable_step_does_not_stop_the_enable(self):
        # Classic IOS declared as IOS-XE collects today; identifying it must
        # not cost it the run. Only a platform with no enable step stops here.
        device = RecordingDevice(
            custom={"double_enable": True},
            outputs={"show version": "Cisco IOS Software, C2960 Software, Version 15.0(2)SE\n"},
        )
        outcome = _collect_device(device, XR_POLICY, self.root)

        self.assertTrue(outcome.connected)
        self.assertIn("enable", device.commands)

    def test_the_identifying_command_is_held_to_the_allowlist(self):
        policy = CommandPolicy({"iosxe": {"parse": ["show inventory"]}})
        device = RecordingDevice(custom={"double_enable": True})
        _collect_device(device, policy, self.root)

        self.assertEqual(device.commands[:2], ["<connect>", "enable"])

    def test_a_show_version_that_fails_before_the_enable_does_not_stop_it(self):
        policy = CommandPolicy({"iosxe": {"parse": ["show version", "show inventory"]}})
        device = RecordingDevice(custom={"double_enable": True}, fail_once=["show version"])
        outcome = _collect_device(device, policy, self.root)

        self.assertTrue(outcome.connected)
        self.assertEqual(device.commands[:3], ["<connect>", "show version", "enable"])


XR_PROMPT = "RP/0/RP0/CPU0:pe-1#\n"

NXOS_BANNER = (
    "Cisco Nexus Operating System (NX-OS) Software\n"
    "TAC support: http://www.cisco.com/tac\n"
    "leaf-1#\n"
)

ASA_BANNER = "Cisco Adaptive Security Appliance Software Version 9.16(4)\nfw-1#\n"

EVERY_POLICY = CommandPolicy({
    "iosxe": {"parse": ["show version"]},
    "iosxr": {"parse": ["show version"]},
    "nxos": {"parse": ["show version"]},
    "asa": {"parse": ["show version"]},
})


class TestTheDeviceIsCollectedAsWhatItProved(DoubleEnableTestCase):
    """A login that proves another OS is logged into again as that OS, once, in the same run."""

    def device(self, *dialogs, **kwargs):
        device = RecordingDevice(dialogs=dialogs, **kwargs)
        device.default._logfile = str(self.root / "dialog.log")
        return device

    def mismatch(self, declared, proven, dialog):
        """The report exactly as it was before the reconnect existed."""
        return "logged in, but " + collector.os_mismatch_hint(declared, proven, dialog.strip())

    def test_an_xr_box_declared_as_ios_xe_is_collected_as_ios_xr_in_one_run_with_no_enable_sent(self):
        device = RecordingDevice(
            custom={"double_enable": True}, outputs={"show version": XR_VERSION}
        )
        outcome = _collect_device(device, XR_POLICY, self.root)

        self.assertTrue(outcome.connected)
        self.assertIsNone(outcome.error)
        self.assertEqual(outcome.os, "iosxr")
        self.assertNotIn("enable", device.commands)
        self.assertEqual(self.dialog_secrets, [])
        # Identified on the first session; collected on a second one whose
        # connection object was built for XR, with XR's session setup.
        self.assertEqual(
            device.commands,
            ["<connect>", "show version", "<destroy>", "<connect>", "show version"],
        )
        self.assertEqual(device.plugins, ["iosxe", "iosxr"])
        self.assertEqual(
            device.connect_kwargs[1]["init_exec_commands"],
            list(platform_for("iosxr").session_setup),
        )

    def test_nx_os_proven_by_its_banner_is_collected_as_nx_os(self):
        device = self.device(NXOS_BANNER, NXOS_BANNER)
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertTrue(outcome.connected)
        self.assertEqual(outcome.os, "nxos")
        self.assertEqual(outcome.detected_os, "nxos")
        self.assertEqual(device.plugins, ["iosxe", "nxos"])
        self.assertEqual(device.commands, ["<connect>", "<destroy>", "<connect>", "show version"])
        # NX-OS's own setup: it refuses the `terminal width 0` IOS-XE sends.
        self.assertEqual(
            device.connect_kwargs[1]["init_exec_commands"],
            list(platform_for("nxos").session_setup),
        )

    def test_the_reconnect_keeps_the_second_enable_where_the_proven_platform_has_one(self):
        device = self.device(ASA_BANNER, ASA_BANNER, custom={"double_enable": True})
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertTrue(outcome.connected)
        self.assertEqual(outcome.os, "asa")
        second = device.commands[device.commands.index("<destroy>"):]
        self.assertEqual(
            second,
            ["<destroy>", "<connect>", "enable", *platform_for("asa").session_setup, "show version"],
        )
        self.assertEqual(device.connect_kwargs[1]["init_exec_commands"], [])

    def test_a_proven_os_with_no_allowlist_is_reported_as_before(self):
        device = self.device(XR_PROMPT)
        outcome = _collect_device(device, POLICY, self.root)

        self.assertFalse(outcome.connected)
        self.assertEqual(device.commands, ["<connect>"])
        self.assertEqual(outcome.os, "iosxe")
        self.assertEqual(outcome.detected_os, "iosxr")
        self.assertEqual(outcome.error, self.mismatch("iosxe", "iosxr", XR_PROMPT))
        self.assertNotIn("declared_os", outcome.as_dict())

    def test_a_second_session_that_proves_yet_another_os_stops_without_a_third_login(self):
        # The first session's XR prompt is still in the transcript. Only what
        # the second session wrote is its evidence; read whole, the prompt
        # would outvote the banner and the device would be collected as XR.
        device = self.device(XR_PROMPT, "Cisco Nexus Operating System (NX-OS) Software\n")
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertFalse(outcome.connected)
        self.assertEqual(device.commands, ["<connect>", "<destroy>", "<connect>"])
        # Reported as today: the declaration and the first proof, so finalize
        # corrects the testbed exactly as it would have, plus what the second
        # login said.
        self.assertEqual(outcome.os, "iosxe")
        self.assertEqual(outcome.detected_os, "iosxr")
        self.assertTrue(outcome.error.startswith(self.mismatch("iosxe", "iosxr", XR_PROMPT)))
        self.assertIn("proved NX-OS instead", outcome.error)
        self.assertIn("not tried a third time", outcome.error)
        self.assertEqual(device.os, "iosxe")


    def test_a_connection_that_cannot_be_dropped_is_not_logged_into_again_under_the_old_plugin(self):
        device = self.device(XR_PROMPT)
        device.destroy_error = RuntimeError("no connection to destroy")
        outcome = _collect_device(device, XR_POLICY, self.root)

        self.assertFalse(outcome.connected)
        self.assertEqual(device.plugins, ["iosxe"])
        self.assertEqual(device.commands, ["<connect>", "<destroy>"])
        self.assertEqual(outcome.error, self.mismatch("iosxe", "iosxr", XR_PROMPT))

    def test_a_retry_after_the_reconnect_logs_in_under_the_proven_os(self):
        policy = CommandPolicy({
            "iosxe": {"parse": ["show version"]},
            "iosxr": {"parse": ["show version", "show inventory"]},
        })
        device = self.device(XR_PROMPT, fail_once=["show inventory"])
        with mock.patch.object(collector, "RETRY_PAUSE", 0):
            outcome = _collect_device(device, policy, self.root)

        self.assertEqual([command.status for command in outcome.commands], ["parsed", "parsed"])
        # The retry reopens the XR connection rather than building another.
        self.assertEqual(device.plugins, ["iosxe", "iosxr"])
        self.assertEqual(
            device.connect_kwargs[2]["init_exec_commands"],
            list(platform_for("iosxr").session_setup),
        )

    def test_the_second_login_and_a_retry_after_it_are_as_quiet_as_the_first(self):
        policy = CommandPolicy({
            "iosxe": {"parse": ["show version"]},
            "iosxr": {"parse": ["show version", "show inventory"]},
        })
        device = self.device(XR_PROMPT, fail_once=["show inventory"])
        with mock.patch.object(collector, "RETRY_PAUSE", 0):
            _collect_device(device, policy, self.root)

        self.assertEqual(len(device.connect_kwargs), 3)
        for kwargs in device.connect_kwargs:
            self.assertIs(kwargs["operating_mode"], True)
            self.assertIs(kwargs["learn_os_version"], False)

    def test_the_manifest_names_the_declaration_only_where_the_device_was_collected_as_another_os(self):
        reconnected = _collect_device(self.device(XR_PROMPT), XR_POLICY, self.root).as_dict()
        self.assertEqual((reconnected["os"], reconnected["declared_os"]), ("iosxr", "iosxe"))

        ordinary = _collect_device(RecordingDevice(), POLICY, self.root).as_dict()
        self.assertNotIn("declared_os", ordinary)
        # The keys every manifest has carried, so an older one reads the same.
        self.assertEqual(
            set(collector.DeviceResult(name="r", os="iosxe", declared_os="iosxe").as_dict()),
            {"name", "os", "platform", "connected", "error", "connect_log", "probed",
             "detected_os", "commands"},
        )

    def test_a_later_session_is_read_from_where_the_earlier_one_ended(self):
        path = self.root / "dialog.log"
        path.write_text(XR_PROMPT, encoding="utf-8")
        start = collector._dialog_size(str(path))
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("leaf-1#\n")

        self.assertEqual(collector.connect_dialog_tail(str(path), start), "leaf-1#")
        self.assertIn("RP/0/RP0/CPU0", collector.connect_dialog_tail(str(path)))


class TestTheReconnectAfterATimeout(DoubleEnableTestCase):
    """A fresh session starts unprivileged again, so it has to enable again."""

    def setUp(self):
        super().setUp()
        self._pause = collector.RETRY_PAUSE
        collector.RETRY_PAUSE = 0

    def tearDown(self):
        collector.RETRY_PAUSE = self._pause
        super().tearDown()

    def test_the_retry_session_is_enabled_before_the_command_is_tried_again(self):
        policy = CommandPolicy({"iosxe": {"parse": ["show version", "show inventory"]}})
        device = RecordingDevice(custom={"double_enable": True}, fail_once=["show inventory"])
        outcome = _collect_device(device, policy, self.root)

        # The device was identified once, on the first session; the retry
        # session is enabled straight away rather than asked again.
        self.assertEqual(
            device.commands,
            [
                "<connect>", "show version", "enable", "terminal length 0",
                "terminal width 0", "show version", "show inventory",
                "<connect>", "enable", "terminal length 0", "terminal width 0",
                "show inventory",
            ],
        )
        self.assertEqual([command.status for command in outcome.commands], ["parsed", "parsed"])
        self.assertEqual(self.dialog_secrets, ["enable-secret", "enable-secret"])

    def test_a_device_whose_session_cannot_be_reopened_is_sent_nothing_more(self):
        """BUG-112: after a final timeout the session is reopened, and a device that cannot be stops.

        The commands after it are recorded as not sent, so the gap list names
        them, rather than being sent into a session that is gone.
        """
        class NeverAnswers(RecordingDevice):
            def execute(self, command, timeout=None, reply=None, **kwargs):
                if command == "show inventory":
                    self.fail_once.add(command)
                return super().execute(command, timeout=timeout, reply=reply, **kwargs)

        policy = CommandPolicy({"iosxe": {"parse": ["show version", "show inventory", "show ip arp"]}})
        # The retry's session opens; the one after the last attempt does not.
        device = NeverAnswers(connect_errors=[None, None, OSError("Connection refused")])
        outcome = _collect_device(device, policy, self.root)

        self.assertEqual(device.commands[-4:], ["show inventory", "<connect>", "show inventory", "<connect>"])
        self.assertNotIn("show ip arp", device.commands)
        self.assertEqual([command.status for command in outcome.commands], ["parsed", "failed", "failed"])
        self.assertIn("reconnecting after it failed", outcome.commands[1].detail)
        self.assertIn("not sent", outcome.commands[2].detail)

    def test_a_device_whose_retry_session_cannot_be_opened_is_sent_nothing_more(self):
        """BUG-112: the reopen for the retry failing stops the device too."""
        policy = CommandPolicy({"iosxe": {"parse": ["show version", "show inventory", "show ip arp"]}})
        device = RecordingDevice(fail_once=["show inventory"], connect_errors=[None, OSError("Connection refused")])
        outcome = _collect_device(device, policy, self.root)

        self.assertEqual(device.commands[-2:], ["show inventory", "<connect>"])
        self.assertNotIn("show ip arp", device.commands)
        self.assertEqual([command.status for command in outcome.commands], ["parsed", "failed", "failed"])
        self.assertIn("not sent", outcome.commands[2].detail)


class TestTheTestbedArgumentsThatLookRightAndDoNothing(DoubleEnableTestCase):
    def device_with_init_commands(self):
        return RecordingDevice(
            connections={
                "cli": {
                    "protocol": "ssh",
                    "arguments": {"init_exec_commands": ["enable", "terminal length 0"]},
                }
            }
        )

    def test_init_exec_commands_in_the_testbed_are_reported_not_silently_dropped(self):
        device = self.device_with_init_commands()
        with self.assertLogs("netstate.collector", level=logging.WARNING) as captured:
            self.collect(device)

        warning = "\n".join(captured.output)
        self.assertIn("connections.cli.arguments.init_exec_commands is ignored", warning)
        self.assertIn("double_enable", warning)

    def test_they_are_still_ignored_because_the_keyword_beats_them(self):
        device = self.device_with_init_commands()
        self.collect(device)

        self.assertEqual(device.connect_kwargs[0]["init_exec_commands"], list(platform_for("iosxe").session_setup))

    def test_a_testbed_that_sets_nothing_produces_no_noise(self):
        device = RecordingDevice(connections={"cli": {"protocol": "ssh", "ip": "10.0.0.11"}})
        with self.assertNoLogs("netstate.collector", level=logging.WARNING):
            self.collect(device)


class TestTellingTheTwoFailuresApart(DoubleEnableTestCase):
    """Which half of the login broke decides where the reader should look."""

    def test_a_device_that_never_answered_is_reported_as_a_failed_connect(self):
        device = RecordingDevice(custom={"double_enable": True})
        device.connect_error = OSError("No route to host")
        outcome = self.collect(device)

        self.assertFalse(outcome.connected)
        self.assertIn("connect failed", outcome.error)
        self.assertIn("No route to host", outcome.error)

    def test_a_device_that_let_us_in_says_so_before_naming_the_enable(self):
        device = RecordingDevice(custom={"double_enable": True}, fail_once=["enable"])
        outcome = self.collect(device)

        self.assertFalse(outcome.connected)
        self.assertIn("logged in", outcome.error)
        self.assertIn("second enable failed", outcome.error)
        # The reader must not be sent to check routing and credentials that
        # demonstrably worked a moment earlier.
        self.assertNotIn("connect failed", outcome.error)

    def test_a_session_that_failed_after_the_login_is_closed(self):
        """BUG-256: the login worked, so a session was open on the device, and through a jump host on that too.

        Left open, every device that failed its second enable, or the session
        setup after it, kept a VTY line, and the jump host a session, until the
        run ended.
        """
        for failing in ("enable", "terminal length 0"):
            with self.subTest(failing=failing):
                device = RecordingDevice(custom={"double_enable": True}, fail_once=[failing])
                with mock.patch.object(device, "disconnect") as disconnect:
                    outcome = self.collect(device)
                self.assertFalse(outcome.connected)
                disconnect.assert_called_once_with()

    def test_the_cause_survives_past_the_first_line_of_a_unicon_error(self):
        # unicon leads with "failed to connect to <name>", which names nothing;
        # the device's own words are on the lines after it.
        device = RecordingDevice()
        device.connect_error = OSError(
            "failed to connect to rbt-hrb-ce2\n"
            "Unable to negotiate with 203.0.113.42 port 22: no matching key "
            "exchange method found."
        )
        outcome = self.collect(device)

        self.assertIn("no matching key exchange method found", outcome.error)


class TestAnAddressThatAteTheLinesBelowIt(unittest.TestCase):
    """YAML folds an indented continuation into the scalar above it.

    A key that lost its name becomes part of the address, and pyATS reports it
    as an IDNA encoding failure — true, and no help at all.
    """

    def load(self, message):
        def loader(_path):
            raise ValueError(message)

        with self.assertRaises(collector.CollectionError) as raised:
            collector._load_testbed(loader, "testbed.yaml")
        return str(raised.exception)

    def test_the_real_failure_names_the_key_that_went_missing(self):
        error = self.load(
            "SchemaError: translate_host('203.0.113.42 -o KexAlgorithms="
            "+diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1 -o "
            "HostKeyAlgorithms=+ssh-rsa') raised UnicodeEncodeError('idna', "
            "'203.0.113.42 -o KexAlgorithms=...', 12, 262, 'label too long')"
        )
        self.assertIn("swallowed the lines below it", error)
        self.assertIn("ssh_options", error)
        # The address it should have held, quoted back ready to paste.
        self.assertIn("ip: 203.0.113.42", error)

    def test_an_address_that_is_merely_wrong_is_not_diagnosed_as_this(self):
        error = self.load("SchemaError: translate_host('not a host') raised gaierror")

        self.assertIn("not an address pyATS can resolve", error)
        self.assertNotIn("swallowed", error)

    def test_the_original_pyats_message_is_kept_either_way(self):
        error = self.load("SchemaError: translate_host('10.0.0.1 -o Ciphers=+3des-cbc') raised x")

        self.assertIn("translate_host", error)
        self.assertIn("SchemaError", error)


class TestFindingTheDialogWhenTheConnectionNeverExisted(OwnTempDirectoryTestCase):
    """A connect that failed early builds no connection object to ask.

    The transcript is still on disk, and it is the only evidence there is.
    """

    def write(self, name, age=0.0):
        path = self.tempdir / name
        path.write_text("dialog", encoding="utf-8")
        if age:
            stamp = time.time() - age
            os.utime(path, (stamp, stamp))
        return path

    def test_the_log_is_found_by_name_when_the_object_cannot_be_asked(self):
        expected = self.write("xa_9006_vpe_1-cli-20260811T134943000.log")
        self.assertEqual(collector._recent_unicon_log("xa_9006_vpe_1"), str(expected))

    def test_the_newest_attempt_wins_over_an_earlier_one(self):
        self.write("xf_9901_pe_1-cli-old.log", age=120)
        newest = self.write("xf_9901_pe_1-cli-new.log")
        self.assertEqual(collector._recent_unicon_log("xf_9901_pe_1"), str(newest))

    def test_a_stale_log_from_a_previous_run_is_not_this_runs_evidence(self):
        # A wrong transcript is worse than none: it would diagnose yesterday.
        self.write("nor_920_pe_1-cli-yesterday.log", age=86_400)
        self.assertIsNone(collector._recent_unicon_log("nor_920_pe_1"))

    def test_another_devices_log_is_never_borrowed(self):
        self.write("xe_hub_920_pe_1-cli-now.log")
        self.assertIsNone(collector._recent_unicon_log("nor_920_pe_1"))

    def test_a_device_name_is_not_read_as_a_glob(self):
        self.write("real-cli-now.log")
        self.assertIsNone(collector._recent_unicon_log("*"))

    def test_a_device_whose_name_extends_this_ones_is_another_device(self):
        """BUG-252: `pe-1-*.log` matched `pe-1-b`'s log too; the name is matched whole."""
        self.write("pe-1-b-cli-20261010T100000000.log")
        self.assertIsNone(collector._recent_unicon_log("pe-1"))
        own = self.write("pe-1-cli-20261010T095900000.log", age=60)
        self.assertEqual(collector._recent_unicon_log("pe-1"), str(own))


class TestTheDialogCopiedIntoTheRunLog(unittest.TestCase):
    """`collect.log` alone should answer "what did the device actually say"."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "unicon.log"

    def tearDown(self):
        self._tmp.cleanup()

    def tail(self, text):
        self.path.write_text(text, encoding="utf-8")
        dialog = collector.connect_dialog_tail(str(self.path))
        with self.assertLogs("netstate.collector", level=logging.WARNING) as captured:
            collector._log_connect_dialog(RecordingDevice(), str(self.path), dialog)
        return "\n".join(captured.output)

    def test_the_devices_own_words_reach_the_run_log(self):
        logged = self.tail(
            "Trying 203.0.113.42...\n"
            "Password: \n"
            "rbt-hrb-ce2#terminal length 0\n"
            "% Invalid input detected at '^' marker.\n"
        )
        self.assertIn("% Invalid input detected", logged)
        self.assertIn("terminal length 0", logged)

    def test_a_credential_in_the_dialog_is_redacted_on_the_way_through(self):
        logged = self.tail("rbt-hrb-ce2#\nenable password Str0ngSecret\n")

        self.assertNotIn("Str0ngSecret", logged)
        self.assertIn(collector.REDACTION_MARKER, logged)

    def test_only_the_tail_is_copied_rather_than_a_whole_session(self):
        logged = self.tail("\n".join(f"line {n}" for n in range(500)))

        self.assertIn("line 499", logged)
        self.assertNotIn("line 400", logged)

    def test_a_missing_dialog_is_never_passed_over_in_silence(self):
        # A failure with no dialog behind it is the dead end this path exists
        # to prevent, so it says which kind of nothing it found.
        with self.assertLogs("netstate.collector", level=logging.WARNING) as captured:
            collector._log_connect_dialog(RecordingDevice(), None, "")
        self.assertIn("could not be located", "\n".join(captured.output))

    def test_an_empty_dialog_is_reported_as_empty_rather_than_skipped(self):
        with self.assertLogs("netstate.collector", level=logging.WARNING) as captured:
            collector._log_connect_dialog(RecordingDevice(), "/tmp/whatever.log", "")
        self.assertIn("is empty", "\n".join(captured.output))

    def test_an_unreadable_log_file_is_not_fatal(self):
        self.assertEqual(collector.connect_dialog_tail(str(self.path / "nope")), "")

    def test_the_evidence_is_read_before_the_redactor_blunts_it(self):
        # "no matching key exchange method found" carries the word 'key', so
        # the redactor takes the algorithm list with it. The hint has to reason
        # over what the device said, not over what is safe to write down.
        self.path.write_text(
            "Unable to negotiate with 203.0.113.42 port 22: no matching key "
            "exchange method found. Their offer: diffie-hellman-group14-sha1\n",
            encoding="utf-8",
        )
        raw = collector.connect_dialog_tail(str(self.path))
        self.assertIn("Their offer: diffie-hellman-group14-sha1", raw)

        redacted, _changed = collector.redact(raw)
        self.assertNotIn("diffie-hellman-group14-sha1", redacted)


class TestTheAdviceOnAFailedConnect(unittest.TestCase):
    """"Failed to connect" is what a privilege problem looks like from outside."""

    def test_a_rejected_session_setup_command_points_at_the_second_enable(self):
        hint = connect_failure_hint(
            RuntimeError("terminal length 0\n% Invalid input detected at '^' marker."),
            double_enable_used=False,
        )
        self.assertIn("double_enable", hint)

    def test_a_command_authorization_failure_points_there_too(self):
        hint = connect_failure_hint(
            RuntimeError("Command authorization failed."), double_enable_used=False
        )
        self.assertIn("double_enable", hint)

    def test_a_device_that_already_double_enables_is_not_told_to_do_it_again(self):
        self.assertIsNone(
            connect_failure_hint(
                RuntimeError("Command authorization failed."), double_enable_used=True
            )
        )

    def test_an_ordinary_unreachable_device_gets_no_guesswork(self):
        self.assertIsNone(
            connect_failure_hint(
                RuntimeError("No route to host"), double_enable_used=False
            )
        )

    def test_the_hint_reads_the_dialog_because_the_exception_says_nothing(self):
        """unicon raises only the first line; every word that explains it is in the log.

        The dialog is written by hand, in the place of one recorded from a
        failed login; the two share only the wording OpenSSH and unicon always
        print. rbt-hrb-ce2 is the old IOS CE of the synthetic Riverbend demo
        network, the address is documentation space, and the spawn id and the
        offer of two legacy key exchanges are chosen for the test.
        """
        hint = connect_failure_hint(
            RuntimeError("failed to connect to rbt-hrb-ce2"),
            double_enable_used=True,
            dialog=(
                "+++ rbt-hrb-ce2 logfile /tmp/rbt-hrb-ce2-cli.log +++\n"
                "+++ Unicon plugin ios (unicon.plugins.ios) +++\n"
                "+++ connection to spawn: ssh -l netops 192.0.2.61 -p 22, id: 4021 +++\n"
                "Unable to negotiate with 192.0.2.61 port 22: no matching key "
                "exchange method found. Their offer: diffie-hellman-group1-sha1,"
                "diffie-hellman-group14-sha1\n"
            ),
        )
        self.assertIn("ssh_options", hint)
        # The fix has to name algorithms, so the hint quotes the ones offered.
        self.assertIn("diffie-hellman-group14-sha1", hint)
        self.assertIn("diffie-hellman-group1-sha1", hint)

    def test_an_exception_that_carries_nothing_and_no_dialog_gets_no_hint(self):
        self.assertIsNone(
            connect_failure_hint(
                RuntimeError("failed to connect to rbt-hrb-ce2"),
                double_enable_used=False,
                dialog="",
            )
        )

    def test_an_unknown_host_key_prompt_is_answered_no_and_says_so(self):
        # The login dialog answers this question "no" (never "yes"); the
        # advice is to pin the key where that ssh client looks, not to
        # silence the question.
        hint = connect_failure_hint(
            RuntimeError("failed to connect to rbt-hrb-ce2"),
            double_enable_used=True,
            dialog=(
                "The authenticity of host '203.0.113.42 (203.0.113.42)' "
                "can't be established.\n"
                "RSA key fingerprint is: SHA256:NPCX1lvqZrkOCDYqKoxjROzAsKJSamPY71HygOSABko\n"
                "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
            ),
        )
        self.assertIn("answered no", hint)
        self.assertIn("never accepts a key by itself", hint)
        self.assertNotIn("jump host", hint)
        self.assertNotIn("accept-new", hint)

    ANSWERED_HOST_KEY = (
        "The authenticity of host '192.0.2.42 (192.0.2.42)' can't be established.\n"
        "RSA key fingerprint is SHA256:NPCX1lvqZrkOCDYqKoxjROzAsKJSamPY71HygOSABko.\n"
        "Are you sure you want to continue connecting (yes/no)? yes\n"
        "Warning: Permanently added '192.0.2.42' (RSA) to the list of known hosts.\n"
    )

    def test_an_answered_host_key_question_does_not_hide_a_refused_password(self):
        """BUG-108: unicon answered the question, so the failure is the one after it."""
        hint = connect_failure_hint(
            RuntimeError("failed to connect to sw-1"),
            double_enable_used=False,
            dialog=self.ANSWERED_HOST_KEY + "Password: \nPassword: \nPermission denied, please try again.\n",
        )
        self.assertNotIn("host key", hint or "")

    def test_an_answered_host_key_question_does_not_hide_a_privilege_problem(self):
        """BUG-108: the hints below the host-key one still get their turn."""
        hint = connect_failure_hint(
            RuntimeError("failed to connect to sw-1"),
            double_enable_used=False,
            dialog=self.ANSWERED_HOST_KEY + "Password: \nsw-1>terminal length 0\n% Authorization failed.\nsw-1>",
        )
        self.assertIn("double_enable", hint)
        self.assertNotIn("host key", hint)

    def test_a_refused_unknown_host_key_still_earns_the_host_key_advice(self):
        hint = connect_failure_hint(
            RuntimeError("failed to connect to sw-1"),
            double_enable_used=False,
            dialog=(
                "No RSA host key is known for 192.0.2.42 and you have requested strict checking.\n"
                "Host key verification failed.\n"
            ),
            known_hosts="/estates/lab/known_hosts",
        )
        self.assertIn("not pinned in /estates/lab/known_hosts", hint)
        self.assertIn("ssh-keyscan 192.0.2.42", hint)
        self.assertNotIn("accept-new", hint)

    def test_an_unpinned_key_off_port_22_is_scanned_on_its_own_port(self):
        hint = connect_failure_hint(
            RuntimeError("failed to connect to sw-1"),
            double_enable_used=False,
            dialog=(
                "No ED25519 host key is known for [192.0.2.42]:2222 and you have requested strict checking.\n"
                "Host key verification failed.\n"
            ),
        )
        self.assertIn("ssh-keyscan -p 2222 192.0.2.42", hint)

    def test_a_refused_host_key_through_a_jump_host_earns_the_advice_with_the_jump_prompt_back(self):
        """BUG-108: the jump host's ssh client refuses the key and exits, and its prompt comes back below.

        The refusal is the last word of that hop whatever the jump host
        prints after it; the dialog does not end on it.
        """
        hint = connect_failure_hint(
            RuntimeError("failed to connect to R1"),
            double_enable_used=False,
            dialog=ROOT_JUMPHOST_DIALOG.replace(
                "Password:\nR1#\n",
                "No ECDSA host key is known for 198.51.100.33 and you have requested strict checking.\n"
                "Host key verification failed.\n"
                "root@jump-01#\n",
            ),
            via_jump_host=True,
        )
        self.assertIn("jump host", hint)
        self.assertIn("that host's known_hosts", hint)
        self.assertNotIn("accept-new", hint)

    def test_a_changed_host_key_is_not_waved_through(self):
        # The opposite advice: this one is a fact about the device, and
        # silencing it is not a documentation tool's call.
        hint = connect_failure_hint(
            RuntimeError("failed to connect"),
            double_enable_used=False,
            dialog=(
                "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n"
                "Host key verification failed."
            ),
        )
        self.assertIn("ssh-keygen -R", hint)
        self.assertNotIn("accept-new", hint)

    def test_a_crypto_mismatch_is_named_as_one_rather_than_as_unreachable(self):
        # The case that splits a fleet in half: an older IOS-XE image offers
        # only legacy algorithms where a current IOS-XR box negotiates fine.
        hint = connect_failure_hint(
            RuntimeError(
                "Unable to negotiate with 203.0.113.42 port 22: no matching "
                "key exchange method found. Their offer: "
                "diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1"
            ),
            double_enable_used=False,
        )
        self.assertIn("ssh_options", hint)

    def test_the_crypto_hint_is_given_even_on_a_double_enable_device(self):
        # Nothing was ever typed, so the enable is irrelevant to this failure.
        hint = connect_failure_hint(
            RuntimeError("Unable to negotiate with 203.0.113.42 port 22"),
            double_enable_used=True,
        )
        self.assertIn("ssh_options", hint)


# The dialog a blackholed management address leaves behind. The jumphost login
# is complete and correct; the last line is the hop command, and nothing
# answered it for the whole 90 seconds the connect was given.
#
# Written by hand, in the place of a dialog recorded from a run. It keeps that
# dialog's lines in their order, which is the order unicon writes them in, and
# nothing else: the device is rbt-dnv-pe3 of the synthetic Riverbend demo
# network, the addresses are documentation space, the login user is a generic
# one, and the spawn id, the times and the gaps between them are made up. The
# jump host's `host/user#` prompt is kept on purpose, because it is the shape
# an ASA context prompt also has.
UNANSWERED_HOP_DIALOG = """\
2026-10-27 10:15:02,410: %UNICON-INFO: +++ rbt-dnv-pe3 logfile /tmp/rbt-dnv-pe3-cli.log +++
2026-10-27 10:15:02,411: %UNICON-INFO: +++ Unicon plugin iosxe (unicon.plugins.iosxe) +++
2026-10-27 10:15:02,420: %UNICON-INFO: connection via proxy jumphost
2026-10-27 10:15:02,438: %UNICON-INFO: +++ connection to spawn: ssh -l netops 192.0.2.10 -p 22, id: 139900000000001 +++
2026-10-27 10:15:02,444: %UNICON-INFO: connection to jumphost
netops@192.0.2.10's password:
Last login: Tue Oct 27 08:47:36 2026 from 203.0.113.7
jump-02/netops#
2026-10-27 10:15:04,228: %UNICON-INFO: Learned hostname: jump-02
jump-02/netops#
2026-10-27 10:15:04,269: %UNICON-INFO: +++ initializing handle +++
2026-10-27 10:15:04,272: %UNICON-INFO: connection to rbt-dnv-pe3
 ssh 198.51.100.33 netops\
"""


class TestAHopNothingAnswered(unittest.TestCase):
    """The one connect failure that arrives as an absence.

    Every other rule in `connect_failure_hint` reads words the device said. On
    a management address that answers nothing there are none: the ssh client on
    the jumphost waits on a TCP connect that never completes, DiscoNet's
    connect timeout ends the attempt before the client's own ~127s can report
    it, and the transcript stops dead on the command. Reported without a hint
    it reads as a credential or crypto problem, which sends the reader to two
    things that were never reached.
    """

    def test_a_dialog_that_ends_on_the_hop_command_is_named_as_silence(self):
        hint = connect_failure_hint(
            RuntimeError("failed to connect to rbt-dnv-pe3"),
            double_enable_used=False,
            dialog=UNANSWERED_HOP_DIALOG,
        )
        self.assertIsNotNone(hint)
        # The address that did not answer is the one fact worth quoting.
        self.assertIn("198.51.100.33", hint)
        # And it must rule out the two things a bare "failed to connect" implies.
        self.assertIn("credentials", hint)
        self.assertIn("crypto", hint)

    def test_the_hint_explains_why_the_dialog_is_empty(self):
        """The timeout ordering is the reason there is nothing to read, so the
        hint quotes the run's real timeout rather than a fixed number."""
        hint = connect_failure_hint(
            RuntimeError("failed to connect to rbt-dnv-pe3"),
            double_enable_used=False,
            dialog=UNANSWERED_HOP_DIALOG,
            connect_timeout=45,
        )
        self.assertIn("45s connect timeout", hint)
        self.assertIn("147", hint)  # what to re-run with, past the TCP timeout

    def test_the_jumphosts_prompt_proves_no_os_for_the_device_behind_it(self):
        # `jump-02/netops#` is the shape an EPNM shell prints, not an ASA
        # context prompt. The device behind it is identified by its own
        # `show version`, never by what the hop in front of it printed.
        self.assertEqual(collector.detect_os(UNANSWERED_HOP_DIALOG), "")


# A root shell as the jump host prints the `user@host#` shape only Junos is
# supposed to print, and the far device is an IOS-XE router with a bare prompt.
# Written the same way as the dialog above: the lines in unicon's order, with
# documentation addresses and made-up times.
ROOT_JUMPHOST_DIALOG = """\
2026-10-26 14:22:40,500: %UNICON-INFO: +++ R1 logfile /tmp/R1-cli.log +++
2026-10-26 14:22:40,502: %UNICON-INFO: +++ Unicon plugin iosxe (unicon.plugins.iosxe) +++
2026-10-26 14:22:40,507: %UNICON-INFO: connection via proxy jumphost
2026-10-26 14:22:40,519: %UNICON-INFO: +++ connection to spawn: ssh -l root 192.0.2.11 -p 22, id: 1 +++
2026-10-26 14:22:40,523: %UNICON-INFO: connection to jumphost
root@192.0.2.11's password:
Last login: Mon Oct 26 13:05:51 2026 from 203.0.113.7
root@jump-01#
2026-10-26 14:22:41,950: %UNICON-INFO: connection to R1
 ssh -l netops 198.51.100.33
Password:
R1#
"""


class TestOnlyTheLastHopIsRead(unittest.TestCase):
    """A prompt is evidence of the OS only when the device behind the last hop printed it."""

    def test_a_root_shell_on_the_jumphost_is_not_read_as_junos(self):
        self.assertEqual(collector.detect_os(ROOT_JUMPHOST_DIALOG), "")
        # Read on its own the same prompt would have been Junos: that is the
        # point of the cut, not an accident of the pattern.
        self.assertEqual(collector.detect_os("root@jump-01#\n"), "junos")

    def test_device_words_keeps_only_what_came_after_the_last_hop(self):
        words = collector.device_words(ROOT_JUMPHOST_DIALOG)
        self.assertNotIn("root@jump-01#", words)
        self.assertNotIn("%UNICON-", words)
        self.assertIn("R1#", words)
        self.assertIn("Password:", words)

    def test_the_jump_prompt_back_after_a_failed_hop_is_not_the_device(self):
        """BUG-149: the hop failed, so the prompt that came back is the jump host's again.

        Read as the device's, `root@jump-01#` proved Junos, and finalize
        rewrote os: junos on an IOS-XE router that never answered.
        """
        refused = ROOT_JUMPHOST_DIALOG.replace(
            "Password:\nR1#\n", "Connection closed by 198.51.100.33 port 22\nroot@jump-01#\n"
        )
        self.assertEqual(collector.detect_os(refused), "")
        self.assertNotIn("root@jump-01#", collector.device_words(refused))
        # The client may say nothing at all; the prompt is still the jump host's.
        silent = ROOT_JUMPHOST_DIALOG.replace("Password:\nR1#\n", "root@jump-01#\n")
        self.assertEqual(collector.detect_os(silent), "")

    def test_nothing_after_the_ssh_clients_failure_is_the_devices(self):
        """BUG-149: a jump host whose prompt reads differently after the hop is cut off too."""
        unreachable = UNANSWERED_HOP_DIALOG + (
            "\nssh: connect to host 198.51.100.33 port 22: No route to host\nnetops@jump-02>\n"
        )
        self.assertEqual(collector.detect_os(unreachable), "")
        self.assertIn("No route to host", collector.device_words(unreachable))

    def test_the_device_behind_the_hop_is_still_proven_by_its_own_prompt(self):
        xr = ROOT_JUMPHOST_DIALOG.replace("R1#\n", "RP/0/RP0/CPU0:XR1#\n")
        self.assertEqual(collector.detect_os(xr), "iosxr")
        junos = ROOT_JUMPHOST_DIALOG.replace("R1#\n", "netops@PE1>\n")
        self.assertEqual(collector.detect_os(junos), "junos")

    def test_the_mismatch_proof_quotes_the_device_not_the_jumphost(self):
        junos = ROOT_JUMPHOST_DIALOG.replace("R1#\n", "netops@PE1>\n")
        hint = collector.os_mismatch_hint("iosxe", "junos", junos)
        self.assertIn("netops@PE1>", hint)
        self.assertNotIn("root@jump-01#", hint)

    def test_a_direct_login_has_no_hop_and_is_read_whole(self):
        self.assertEqual(
            collector.detect_os(
                "+++ connection to spawn: ssh -l admin 10.0.0.1, id: 1 +++\n"
                "Password:\nRP/0/RP0/CPU0:XR1#\n"
            ),
            "iosxr",
        )

    def test_the_jumphosts_own_spawn_line_is_not_read_as_an_unanswered_hop(self):
        # unicon announces the first spawn with a decorated line that also
        # contains an ssh command. A device that failed at that point has said
        # nothing yet either, but the cause is not a silent far end.
        self.assertIsNone(
            collector._unanswered_hop(
                "+++ connection to spawn: ssh -l netops 192.0.2.10 -p 22, id: 1399 +++"
            )
        )

    def test_a_device_that_said_something_is_diagnosed_from_what_it_said(self):
        # The crypto rule still wins: the hop was answered, just not usefully.
        hint = connect_failure_hint(
            RuntimeError("failed to connect to rbt-dnv-pe3"),
            double_enable_used=False,
            dialog=(
                UNANSWERED_HOP_DIALOG + "\n"
                "Unable to negotiate with 198.51.100.33 port 22: no matching key "
                "exchange method found. Their offer: diffie-hellman-group14-sha1"
            ),
        )
        self.assertIn("ssh_options", hint)

    def test_an_ordinary_unreachable_device_still_gets_no_guesswork(self):
        # Deliberate, and encoded twice now: "No route to host" is its own
        # diagnosis. This rule fires on silence, not on every failed connect.
        self.assertIsNone(
            connect_failure_hint(
                RuntimeError("failed to connect"),
                double_enable_used=False,
                dialog="ssh: connect to host 198.51.100.33 port 22: No route to host",
            )
        )

    def test_the_address_is_found_whichever_side_the_username_is_written(self):
        # `ssh -l user host` is OpenSSH; `ssh host user` is the ADE-OS shell on
        # a Cisco appliance used as a jump host, the form the dialog above uses.
        self.assertEqual(collector._unanswered_hop(" ssh 198.51.100.33 netops"), "198.51.100.33")
        self.assertEqual(collector._unanswered_hop("ssh -l netops 198.51.100.33"), "198.51.100.33")
        self.assertEqual(collector._unanswered_hop("ssh netops@198.51.100.33"), "198.51.100.33")
        self.assertEqual(collector._unanswered_hop("ssh -p 2022 198.51.100.33"), "198.51.100.33")

    def test_a_hop_with_no_address_still_reports_the_silence(self):
        # "" not None: there is nothing to quote, but the finding stands.
        self.assertEqual(collector._unanswered_hop("ssh -v"), "")
        hint = connect_failure_hint(
            RuntimeError("failed to connect"), double_enable_used=False, dialog="ssh -v"
        )
        self.assertIsNotNone(hint)
        self.assertNotIn(" to  was", hint)


class TestAnEmptyUsername(DoubleEnableTestCase):
    """`%ENV{DISCONET_USERNAME}` with nothing behind it must be named, not spawned."""

    def test_a_default_credential_that_resolved_to_nothing_is_refused_before_connecting(self):
        device = RecordingDevice(credentials={"default": {"username": "", "password": "p"}})
        result = self.collect(device)
        self.assertFalse(result.connected)
        self.assertIn("DISCONET_USERNAME", result.error)
        self.assertIn("estates/<name>/.env", result.error)
        self.assertEqual(device.connect_kwargs, [])

    def test_a_secret_string_username_is_read_through_its_plaintext(self):
        device = RecordingDevice(credentials={"default": {"username": FakeSecret("netops"), "password": "p"}})
        self.assertEqual(collector.login_username(device), "netops")

    def test_a_testbed_with_no_default_credential_is_left_to_unicon(self):
        # A hand-written testbed may carry the login on the connection; nothing
        # here can tell, so nothing here refuses it.
        device = RecordingDevice(credentials={"enable": {"password": "x"}})
        self.assertIsNone(collector.login_username(device))
        self.assertTrue(self.collect(device).connected)


KEX_REFUSED = (
    "Unable to negotiate with 10.0.0.12 port 22: no matching key exchange method found. "
    "Their offer: diffie-hellman-group1-sha1,diffie-hellman-group14-sha1\n"
)
HOSTKEY_REFUSED = (
    "Unable to negotiate with 10.0.0.12 port 22: no matching host key type found. "
    "Their offer: ssh-rsa,ssh-dss\n"
)
CIPHER_REFUSED = (
    "Unable to negotiate with 10.0.0.12 port 22: no matching cipher found. "
    "Their offer: aes128-cbc,3des-cbc\n"
)
CONNECT_FAILED = RuntimeError('failed to connect to emo_mce_1\nFailed while bringing device to "any" state')
LOGIN_REFUSED = "Permission denied, please try again.\n"
KEX_OPTION = "-o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1"


class TestTheLegacySshRetry(DoubleEnableTestCase):
    """With --allow-legacy-ssh, an ssh client that shares no algorithm with the
    device is given the ones the device offered, and logs in again, in the same run."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(collector, "client_algorithms", return_value=None)
        self.client = patcher.start()
        self.addCleanup(patcher.stop)

    def collect(self, device, **kwargs):
        kwargs.setdefault("allow_legacy_ssh", True)
        return super().collect(device, **kwargs)

    def device(self, *dialogs, errors=(), connection=None, **kwargs):
        connection = dict(connection or {"protocol": "ssh", "ip": "10.0.0.12"})
        device = RecordingDevice(
            dialogs=dialogs, connect_errors=list(errors),
            connections={"cli": connection}, **kwargs,
        )
        device.default._logfile = str(self.root / "dialog.log")
        return device

    def test_a_refused_key_exchange_is_logged_in_again_with_what_the_device_offered(self):
        device = self.device(KEX_REFUSED, "pe-1#\n", errors=[CONNECT_FAILED, None])
        outcome = self.collect(device)

        self.assertTrue(outcome.connected)
        self.assertIsNone(outcome.error)
        self.assertEqual(device.commands, ["<connect>", "<destroy>", "<connect>", "show version"])
        self.assertEqual(device.connections["cli"]["ssh_options"], KEX_OPTION)
        self.assertEqual(outcome.ssh_options, KEX_OPTION)
        self.assertEqual(outcome.as_dict()["ssh_options"], KEX_OPTION)

    def test_each_family_the_client_refuses_is_added_in_turn_from_its_own_refusal(self):
        device = self.device(
            KEX_REFUSED, HOSTKEY_REFUSED, CIPHER_REFUSED, "pe-1#\n",
            errors=[CONNECT_FAILED, CONNECT_FAILED, CONNECT_FAILED, None],
        )
        outcome = self.collect(device)

        self.assertTrue(outcome.connected)
        self.assertEqual(device.commands.count("<connect>"), 4)
        self.assertEqual(
            outcome.ssh_options,
            f"{KEX_OPTION} -o HostKeyAlgorithms=+ssh-rsa,ssh-dss -o Ciphers=+aes128-cbc,3des-cbc",
        )

    def test_the_offer_is_narrowed_to_what_this_machines_client_can_speak(self):
        self.client.return_value = {"kex": ("diffie-hellman-group14-sha1", "curve25519-sha256")}
        device = self.device(KEX_REFUSED, "pe-1#\n", errors=[CONNECT_FAILED, None])
        outcome = self.collect(device)

        self.assertEqual(outcome.ssh_options, "-o KexAlgorithms=+diffie-hellman-group14-sha1")

    def test_an_offer_this_client_cannot_speak_at_all_is_reported_and_never_tried(self):
        self.client.return_value = {"kex": ("curve25519-sha256",)}
        device = self.device(KEX_REFUSED, errors=[CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertFalse(outcome.connected)
        self.assertEqual(device.commands, ["<connect>"])
        self.assertIsNone(outcome.ssh_options)
        self.assertIn("cannot speak", outcome.error)
        self.assertIn("diffie-hellman-group1-sha1, diffie-hellman-group14-sha1", outcome.error)

    def test_the_same_refusal_after_the_option_was_added_stops_the_retry(self):
        device = self.device(KEX_REFUSED, KEX_REFUSED, errors=[CONNECT_FAILED, CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>", "<destroy>", "<connect>"])
        self.assertIsNone(outcome.ssh_options)
        self.assertIn("never reached it", outcome.error)
        self.assertIn("share no algorithm", outcome.error)

    def test_a_telnet_device_is_never_given_ssh_options(self):
        device = self.device(
            KEX_REFUSED, errors=[CONNECT_FAILED],
            connection={"protocol": "telnet", "ip": "10.0.0.12", "port": 23},
        )
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>"])
        self.assertNotIn("ssh_options", device.connections["cli"])
        self.assertIsNone(outcome.ssh_options)

    def test_through_a_jump_host_the_offer_is_not_narrowed_by_this_machines_client(self):
        # The ssh that negotiates runs on the jump host; what this machine's
        # client can speak says nothing about it.
        self.client.return_value = {"kex": ("curve25519-sha256",)}
        device = self.device(
            KEX_REFUSED, "pe-1#\n", errors=[CONNECT_FAILED, None],
            connection={"protocol": "ssh", "ip": "10.0.0.12", "proxy": "jumphost"},
        )
        outcome = self.collect(device)

        self.assertEqual(outcome.ssh_options, KEX_OPTION)

    def test_a_login_refused_after_the_negotiation_keeps_the_options_that_got_it_there(self):
        device = self.device(KEX_REFUSED, LOGIN_REFUSED, errors=[CONNECT_FAILED, CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertFalse(outcome.connected)
        self.assertEqual(outcome.ssh_options, KEX_OPTION)
        self.assertEqual(outcome.as_dict()["ssh_options"], KEX_OPTION)
        self.assertIn("connect failed", outcome.error)
        # The refusal is the device's, and the report says nothing about
        # algorithms: those were settled before the device said a word.
        self.assertNotIn("never reached it", outcome.error)
        self.assertNotIn("algorithm", outcome.error)

    def test_options_the_testbed_already_carries_stay_in_front_of_what_is_added(self):
        device = self.device(
            KEX_REFUSED, "pe-1#\n", errors=[CONNECT_FAILED, None],
            connection={"protocol": "ssh", "ip": "10.0.0.12", "ssh_options": "-o StrictHostKeyChecking=accept-new"},
        )
        outcome = self.collect(device)

        self.assertEqual(outcome.ssh_options, f"-o StrictHostKeyChecking=accept-new {KEX_OPTION}")

    def test_a_connection_that_cannot_be_dropped_is_reported_as_the_refusal_it_was(self):
        device = self.device(KEX_REFUSED, errors=[CONNECT_FAILED])
        device.destroy_error = RuntimeError("no connection")
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>", "<destroy>"])
        self.assertIsNone(outcome.ssh_options)
        self.assertIn("share no algorithm", outcome.error)

    def test_a_failure_that_is_not_a_negotiation_is_not_retried(self):
        device = self.device(LOGIN_REFUSED, errors=[CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>"])
        self.assertNotIn("ssh_options", device.connections["cli"])

    def test_the_second_login_is_as_quiet_as_the_first(self):
        device = self.device(KEX_REFUSED, "pe-1#\n", errors=[CONNECT_FAILED, None])
        self.collect(device)

        for kwargs in device.connect_kwargs:
            self.assertIs(kwargs["operating_mode"], True)
            self.assertIs(kwargs["learn_os_version"], False)
            self.assertEqual(kwargs["init_config_commands"], [])

    def test_a_device_collected_without_any_of_this_records_no_ssh_options(self):
        device = self.device("pe-1#\n", errors=[None])
        outcome = self.collect(device)

        self.assertNotIn("ssh_options", outcome.as_dict())


class TestReadingTheRefusal(unittest.TestCase):
    """What one ssh refusal asks for, in the client's own option syntax."""

    def test_the_key_exchange_offer_becomes_the_kex_option_in_the_plus_form(self):
        fix = collector.legacy_ssh_fix(KEX_REFUSED, None)
        self.assertEqual(fix.family, "kex")
        self.assertEqual(fix.option, KEX_OPTION)
        self.assertEqual(fix.unknown, ())

    def test_a_host_key_refusal_names_the_host_key_option(self):
        fix = collector.legacy_ssh_fix(HOSTKEY_REFUSED, {"key": ("ssh-rsa", "ssh-ed25519")})
        self.assertEqual(fix.option, "-o HostKeyAlgorithms=+ssh-rsa")
        self.assertEqual(fix.unknown, ("ssh-dss",))

    def test_a_dialog_with_no_refusal_asks_for_nothing(self):
        self.assertIsNone(collector.legacy_ssh_fix(LOGIN_REFUSED, None))
        self.assertIsNone(collector.legacy_ssh_fix("", None))

    def test_a_refusal_with_no_offer_asks_for_nothing(self):
        self.assertIsNone(collector.legacy_ssh_fix("no matching cipher found.\n", None))

    def test_a_family_the_client_was_not_asked_about_is_not_filtered(self):
        fix = collector.legacy_ssh_fix(CIPHER_REFUSED, {"kex": ()})
        self.assertEqual(fix.option, "-o Ciphers=+aes128-cbc,3des-cbc")


class TestAskingTheClientWhatItSpeaks(unittest.TestCase):
    def setUp(self):
        collector._client_algorithms.cache_clear()
        self.addCleanup(collector._client_algorithms.cache_clear)

    def test_the_four_families_are_read_from_ssh_dash_q(self):
        def run(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout=f"{argv[2]}-a\n{argv[2]}-b\n")

        with mock.patch.object(collector.subprocess, "run", side_effect=run):
            known = collector.client_algorithms()
        self.assertEqual(known["kex"], ("kex-a", "kex-b"))
        self.assertEqual(sorted(known), ["cipher", "kex", "key", "mac"])

    def test_no_client_on_this_machine_filters_nothing(self):
        with mock.patch.object(collector.subprocess, "run", side_effect=OSError("no ssh")):
            self.assertIsNone(collector.client_algorithms())

    def test_the_client_is_asked_once_per_process(self):
        calls: list[list[str]] = []

        def run(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout="x\n")

        with mock.patch.object(collector.subprocess, "run", side_effect=run):
            collector.client_algorithms()
            collector.client_algorithms()
        self.assertEqual(len(calls), 4)


NXOS_VERSION = (
    "Cisco Nexus Operating System (NX-OS) Software\n"
    "TAC support: http://www.cisco.com/tac\n"
    "  NXOS: version 9.3(8)\n"
)
XE_VERSION = "Cisco IOS XE Software, Version 17.09.04a\nCisco IOS Software [Cupertino], ...\n"
CLASSIC_IOS_VERSION = "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 15.0(2)SE\n"
PLAIN_PROMPT = "leaf-1#\n"


class TestAnUnprovenLoginIsSettledByShowVersion(DoubleEnableTestCase):
    """A bare `hostname#` proves nothing, so the device is asked before anything else is sent."""

    def device(self, version, *dialogs, **kwargs):
        device = RecordingDevice(dialogs=dialogs or (PLAIN_PROMPT,), outputs={"show version": version}, **kwargs)
        device.default._logfile = str(self.root / "dialog.log")
        return device

    def test_a_nexus_behind_a_plain_prompt_is_collected_as_nx_os_in_the_same_run(self):
        device = self.device(NXOS_VERSION, PLAIN_PROMPT, PLAIN_PROMPT)
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertTrue(outcome.connected)
        self.assertIsNone(outcome.error)
        self.assertEqual((outcome.os, outcome.declared_os, outcome.detected_os), ("nxos", "iosxe", "nxos"))
        self.assertEqual(
            device.commands,
            ["<connect>", "show version", "<destroy>", "<connect>", "show version"],
        )
        self.assertEqual(device.plugins, ["iosxe", "nxos"])

    def test_a_show_version_that_agrees_costs_one_command_and_no_second_login(self):
        device = self.device(XE_VERSION)
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertEqual((outcome.os, outcome.declared_os, outcome.detected_os), ("iosxe", None, None))
        self.assertEqual(device.commands, ["<connect>", "show version"])
        self.assertNotIn("declared_os", outcome.as_dict())

    def test_the_identifying_answer_is_the_one_collected(self):
        """BUG-344: a plain prompt's `show version` was sent to identify it, then sent again to collect."""
        device = self.device(XE_VERSION)
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertEqual(device.commands, ["<connect>", "show version"])
        [result] = outcome.commands
        self.assertEqual((result.command, result.status), ("show version", "parsed"))
        self.assertIn("17.09.04a", (self.root / result.raw_file).read_text(encoding="utf-8"))

    def test_an_identifying_answer_that_said_nothing_is_not_the_one_collected(self):
        """BUG-344: an empty answer identified nothing, so the collection asks for its own sample."""
        device = self.device(XE_VERSION)
        answers = ["", XE_VERSION]
        recorded = device.execute

        def execute(command, timeout=None, reply=None, **kwargs):
            output = recorded(command, timeout=timeout, reply=reply, **kwargs)
            return answers.pop(0) if command == "show version" and answers else output

        device.execute = execute
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertEqual(device.commands, ["<connect>", "show version", "show version"])
        [result] = outcome.commands
        self.assertIn("17.09.04a", (self.root / result.raw_file).read_text(encoding="utf-8"))

    def test_classic_ios_under_an_ios_xe_declaration_is_not_a_mismatch(self):
        # It reads through the same allowlist and parsers; a second login
        # would buy nothing, and finalize has nothing to correct.
        device = self.device(CLASSIC_IOS_VERSION)
        policy = CommandPolicy({"iosxe": {"parse": ["show version"]}, "ios": {"parse": ["show version"]}})
        outcome = _collect_device(device, policy, self.root)

        self.assertEqual((outcome.os, outcome.declared_os, outcome.detected_os), ("iosxe", None, None))
        self.assertEqual(device.plugins, ["iosxe"])

    def test_a_show_version_that_fails_leaves_the_declaration_standing(self):
        device = self.device(XE_VERSION, fail_once=["show version"])
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertTrue(outcome.connected)
        self.assertEqual(outcome.os, "iosxe")
        self.assertEqual(device.commands, ["<connect>", "show version", "show version"])

    def test_a_prompt_that_proves_the_os_is_not_asked(self):
        device = self.device(NXOS_VERSION, XR_PROMPT, XR_PROMPT)
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertEqual(outcome.os, "iosxr")
        self.assertEqual(device.commands, ["<connect>", "<destroy>", "<connect>", "show version"])

    def test_a_double_enable_session_that_asked_before_its_enable_is_not_asked_twice(self):
        device = self.device(XE_VERSION, custom={"double_enable": True})
        _collect_device(device, EVERY_POLICY, self.root)

        self.assertEqual(device.commands.count("show version"), 2)
        self.assertEqual(device.commands[:3], ["<connect>", "show version", "enable"])

    def test_the_identifying_command_is_held_to_the_declared_allowlist(self):
        device = self.device(NXOS_VERSION)
        policy = CommandPolicy({"iosxe": {"parse": ["show inventory"]}, "nxos": {"parse": ["show version"]}})
        outcome = _collect_device(device, policy, self.root)

        self.assertEqual(outcome.os, "iosxe")
        self.assertNotIn("show version", device.commands[:2])


    def test_the_report_names_the_prompt_or_the_banner_where_that_was_the_proof(self):
        self.assertIn("the login prompt is IOS-XR (RP/0/RP0/CPU0:pe-1#)",
                      collector.os_mismatch_hint("iosxe", "iosxr", XR_PROMPT))
        self.assertIn("the login banner names NX-OS", collector.os_mismatch_hint("iosxe", "nxos", NXOS_BANNER))


class TestAStandInIsNotAMismatch(unittest.TestCase):
    def test_classic_ios_stands_in_for_ios_xe_and_not_the_other_way_round(self):
        from netstate import platforms

        self.assertTrue(platforms.stands_in("ios", "iosxe"))
        self.assertFalse(platforms.stands_in("iosxe", "ios"))
        self.assertTrue(platforms.stands_in("nxos", "nxos"))
        self.assertFalse(platforms.stands_in("nxos", "iosxe"))
        self.assertFalse(platforms.stands_in("", "iosxe"))
        self.assertFalse(platforms.stands_in("no-such-os", "iosxe"))

    def test_a_banner_naming_classic_ios_under_an_ios_xe_declaration_is_not_chased(self):
        device = RecordingDevice(dialogs=["Cisco IOS Software, C2960\nsw-1#\n"])
        device.default._logfile = str(Path(tempfile.mkdtemp()) / "dialog.log")
        outcome = _collect_device(device, POLICY, Path(tempfile.mkdtemp()))

        self.assertTrue(outcome.connected)
        self.assertEqual(device.plugins, ["iosxe"])
        self.assertIsNone(outcome.error)


class TestTheCredentialSetIsRecorded(unittest.TestCase):
    """The manifest says which set a device was tried under, by number and never by value."""

    def test_the_number_is_read_from_the_testbed_text_and_a_crawled_device_records_none(self):
        directory = Path(tempfile.mkdtemp())
        path = directory / "testbed.yaml"
        path.write_text(
            "testbed:\n  name: lab\ndevices:\n"
            "  pe-1:\n    os: iosxe\n    credentials:\n      default:\n"
            '        username: "%ENV{DISCONET_USERNAME_2}"\n'
            '        password: "%ENV{DISCONET_PASSWORD_2}"\n'
            "  pe-2:\n    os: iosxe\n",
            encoding="utf-8",
        )
        results = [collector.DeviceResult(name="pe-1"), collector.DeviceResult(name="pe-2"),
                   collector.DeviceResult(name="sw-crawled")]
        collector._annotate_credential_sets(results, path)

        self.assertEqual([r.credential_set for r in results], ["2", "1", None])
        self.assertEqual(results[0].as_dict()["credential_set"], "2")
        self.assertNotIn("credential_set", results[2].as_dict())
        self.assertNotIn("%ENV", json.dumps(results[0].as_dict()))

    def test_the_set_is_recorded_on_the_result_as_it_is_collected(self):
        device = RecordingDevice(dialogs=["pe-1#\n"])
        device.default._logfile = str(Path(tempfile.mkdtemp()) / "dialog.log")
        outcome = _collect_device(device, POLICY, Path(tempfile.mkdtemp()), credential_set="2")

        self.assertEqual(outcome.credential_set, "2")
        self.assertEqual(outcome.as_dict()["credential_set"], "2")

    def test_a_username_that_resolved_to_nothing_is_reported_under_the_set_the_block_names(self):
        device = RecordingDevice(credentials={"default": {"username": "", "password": "x"}})
        outcome = _collect_device(device, POLICY, Path(tempfile.mkdtemp()), credential_set="3")

        self.assertEqual(device.commands, [])
        self.assertIn("%ENV{DISCONET_USERNAME_3} resolved to nothing", outcome.error)
        self.assertIn("Set DISCONET_USERNAME_3 in .env", outcome.error)

        first = _collect_device(device, POLICY, Path(tempfile.mkdtemp()), credential_set="1")
        self.assertIn("%ENV{DISCONET_USERNAME} resolved to nothing", first.error)

    def test_a_testbed_that_cannot_be_read_records_nothing_and_raises_nothing(self):
        results = [collector.DeviceResult(name="pe-1")]
        collector._annotate_credential_sets(results, "/no/such/testbed.yaml")
        self.assertIsNone(results[0].credential_set)


UNICON_PLUGIN_LINE = (
    "2026-09-29 10:06:56,754: %UNICON-INFO: +++ Unicon plugin iosxe (unicon.plugins.iosxe) +++\n"
    "2026-09-29 10:06:56,769: %UNICON-INFO: +++ connection to spawn: ssh -l user 10.0.0.12, id: 1 +++\n"
)


class TestUniconsOwnLinesProveNothing(DoubleEnableTestCase):
    """unicon logs the plugin it was told to use; that is the guess, not the evidence."""

    def test_the_plugin_line_does_not_prove_the_declared_os(self):
        self.assertEqual(collector.detect_os(UNICON_PLUGIN_LINE + "leaf-1#\n"), "")
        self.assertEqual(collector.detect_os(UNICON_PLUGIN_LINE), "")

    def test_a_banner_after_the_plugin_line_is_still_read(self):
        self.assertEqual(collector.detect_os(UNICON_PLUGIN_LINE + NXOS_BANNER), "nxos")
        self.assertEqual(collector.detect_os(UNICON_PLUGIN_LINE + XR_PROMPT), "iosxr")

    def test_a_nexus_behind_a_plain_prompt_is_still_asked_show_version_under_a_real_unicon_log(self):
        device = RecordingDevice(
            dialogs=[UNICON_PLUGIN_LINE + PLAIN_PROMPT, UNICON_PLUGIN_LINE + PLAIN_PROMPT],
            outputs={"show version": NXOS_VERSION},
        )
        device.default._logfile = str(self.root / "dialog.log")
        outcome = _collect_device(device, EVERY_POLICY, self.root)

        self.assertEqual((outcome.os, outcome.declared_os), ("nxos", "iosxe"))
        self.assertEqual(device.plugins, ["iosxe", "nxos"])

    def test_a_failed_login_under_the_plugin_records_no_detected_os(self):
        device = RecordingDevice(
            dialogs=[UNICON_PLUGIN_LINE + LOGIN_REFUSED], connect_errors=[CONNECT_FAILED],
        )
        device.default._logfile = str(self.root / "dialog.log")
        outcome = _collect_device(device, POLICY, self.root)

        self.assertIsNone(outcome.detected_os)


class TestTheRunLogCopyLosesTheTestbedSecrets(DoubleEnableTestCase):
    """BUG-072: the dialog copied into collect.log is masked like every other transcript.

    A password typed at a prompt that names no keyword (a `Username:` after a
    banner that ended in `password:`) is invisible to the line redaction;
    only the literal pass over the testbed's secrets finds it.
    """

    ECHOED = "Username: Hop!Pass77\n% Login invalid\nUsername:\n"

    def test_a_secret_with_no_keyword_beside_it_never_reaches_the_run_log(self):
        device = RecordingDevice(dialogs=[self.ECHOED], connect_errors=[CONNECT_FAILED])
        device.default._logfile = str(self.root / "dialog.log")
        with self.assertLogs("netstate.collector", level=logging.DEBUG) as captured:
            outcome = _collect_device(device, POLICY, self.root, secrets={"Hop!Pass77"})
        logged = "\n".join(captured.output)

        self.assertFalse(outcome.connected)
        self.assertIn("% Login invalid", logged)
        self.assertNotIn("Hop!Pass77", logged)

    def test_a_login_prompts_answer_is_logged_by_its_length_only(self):
        prompts = [collector.LoginPrompt(r"Token:\s*$", "Hop!Pass77", "jump-1")]
        device = RecordingDevice()
        with mock.patch.object(collector, "login_dialog", return_value=object()):
            with self.assertLogs("netstate.collector", level=logging.DEBUG) as captured:
                _collect_device(device, POLICY, self.root, prompts=prompts)
        logged = "\n".join(captured.output)

        self.assertIn("Token:", logged)
        self.assertNotIn("Hop!Pass77", logged)


class TestARefusedPasswordIsNotAPrivilegeProblem(unittest.TestCase):
    def test_the_ssh_clients_permission_denied_earns_no_second_enable_advice(self):
        exc = RuntimeError("failed to connect to R1")
        dialog = "user@10.0.0.12's password:\nPermission denied, please try again.\n"
        hint = connect_failure_hint(exc, False, dialog, 30) or ""
        self.assertNotIn("double_enable", hint)
        self.assertNotIn("session setup command", hint)

    def test_a_devices_own_permission_denied_after_login_still_does(self):
        exc = RuntimeError("failed to connect to R1")
        dialog = "sw-1>terminal length 0\n% Permission denied\nsw-1>"
        hint = connect_failure_hint(exc, False, dialog, 30)
        self.assertIn("double_enable", hint)


SHORT_HOST_KEY = "ssh_dispatch_run_fatal: Connection to 10.0.0.12 port 22: Invalid key length\n"
OPTION_UNKNOWN = "command-line line 0: Bad configuration option: requiredrsasize\n"


# Where DiscoNet's own ssh client cannot take a short-key login over (no
# asyncssh, a jump host's client): what is left is what OpenSSH said. The
# relay itself is exercised in test_legacyssh.
NO_RELAY = "DiscoNet's own ssh client is not available here"


class TestAnRsaHostKeyTooShortForAnyOpenSsh(DoubleEnableTestCase):
    """Old IOS presents a 512-bit host key. OpenSSH's floor is 1024 and no option lowers it."""

    def setUp(self):
        super().setUp()
        for name, value in (("client_algorithms", None), ("relay_connection", NO_RELAY)):
            patcher = mock.patch.object(collector, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def collect(self, device, **kwargs):
        kwargs.setdefault("allow_legacy_ssh", True)
        return super().collect(device, **kwargs)

    def device(self, *dialogs, errors=()):
        device = RecordingDevice(
            dialogs=dialogs, connect_errors=list(errors),
            connections={"cli": {"protocol": "ssh", "ip": "10.0.0.12"}},
        )
        device.default._logfile = str(self.root / "dialog.log")
        return device

    def test_the_refusal_names_no_option_because_none_lifts_it(self):
        self.assertIsNone(collector.legacy_ssh_fix(SHORT_HOST_KEY, None))


    def test_the_algorithms_found_before_the_key_was_refused_are_still_kept(self):
        # The negotiation got as far as the host key; what got it there is
        # worth writing down for the day the device is reachable.
        device = self.device(KEX_REFUSED, SHORT_HOST_KEY, errors=[CONNECT_FAILED, CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertEqual(outcome.ssh_options, KEX_OPTION)
        self.assertIn("under 1024 bits", outcome.error)

    def test_an_option_the_client_does_not_know_is_reported_and_not_recorded(self):
        # Reached only through a family the retry does add; the guard is
        # general, so it is proved with a refusal that has an offer.
        device = self.device(KEX_REFUSED, OPTION_UNKNOWN, errors=[CONNECT_FAILED, CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertIsNone(outcome.ssh_options)
        self.assertNotIn("KexAlgorithms", device.connections["cli"].get("ssh_options", ""))
        self.assertIn("does not know", outcome.error)


class TestTheTelnetFallback(DoubleEnableTestCase):
    """With both opt-ins, where no ssh client can talk to the device and TCP/23
    answers, the login goes over telnet."""

    def setUp(self):
        super().setUp()
        for name, value in (("client_algorithms", None), ("port_answers", True), ("relay_connection", NO_RELAY)):
            patcher = mock.patch.object(collector, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def collect(self, device, **kwargs):
        kwargs.setdefault("allow_legacy_ssh", True)
        kwargs.setdefault("allow_telnet", True)
        return super().collect(device, **kwargs)

    def device(self, *dialogs, errors=(), connection=None):
        connection = dict(connection or {"protocol": "ssh", "ip": "10.0.0.12"})
        device = RecordingDevice(
            dialogs=dialogs, connect_errors=list(errors), connections={"cli": connection},
        )
        device.default._logfile = str(self.root / "dialog.log")
        return device

    def test_a_host_key_no_client_takes_is_followed_by_a_telnet_login(self):
        device = self.device(SHORT_HOST_KEY, "sw-1#\n", errors=[CONNECT_FAILED, None])
        outcome = self.collect(device)

        self.assertTrue(outcome.connected)
        self.assertIsNone(outcome.error)
        self.assertEqual(outcome.protocol, "telnet")
        self.assertEqual(outcome.as_dict()["protocol"], "telnet")
        self.assertIsNone(outcome.ssh_options)
        self.assertEqual(device.connections["cli"]["protocol"], "telnet")
        self.assertEqual(device.connections["cli"]["port"], 23)
        self.assertEqual(device.commands[:3], ["<connect>", "<destroy>", "<connect>"])
        self.port_answers.assert_called_once_with("10.0.0.12", 23)

    def test_the_algorithms_found_on_the_way_are_dropped_once_telnet_is_the_way_in(self):
        device = self.device(KEX_REFUSED, SHORT_HOST_KEY, "sw-1#\n", errors=[CONNECT_FAILED, CONNECT_FAILED, None])
        outcome = self.collect(device)

        self.assertEqual(outcome.protocol, "telnet")
        self.assertIsNone(outcome.ssh_options)
        self.assertNotIn("ssh_options", device.connections["cli"])

    def test_a_silent_port_23_is_named_and_the_ssh_refusal_stands(self):
        self.port_answers.return_value = False
        device = self.device(SHORT_HOST_KEY, errors=[CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>"])
        self.assertIsNone(outcome.protocol)
        self.assertIn("under 1024 bits", outcome.error)
        self.assertIn("TCP/23 did not answer", outcome.error)
        self.assertEqual(device.connections["cli"]["protocol"], "ssh")

    def test_a_device_behind_a_jump_host_is_not_probed_from_here(self):
        self.port_answers.side_effect = AssertionError("probed through a proxy")
        device = self.device(
            SHORT_HOST_KEY, errors=[CONNECT_FAILED],
            connection={"protocol": "ssh", "ip": "10.0.0.12", "proxy": "jumphost"},
        )
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>"])
        self.assertIsNone(outcome.protocol)

    def test_a_refused_password_is_never_a_reason_to_try_telnet(self):
        self.port_answers.side_effect = AssertionError("probed after a refused password")
        device = self.device(LOGIN_REFUSED, errors=[CONNECT_FAILED])
        outcome = self.collect(device)

        self.assertEqual(device.commands, ["<connect>"])
        self.assertIsNone(outcome.protocol)

    def test_a_telnet_login_that_fails_keeps_the_ssh_refusal_as_the_report_and_puts_ssh_back(self):
        device = self.device(SHORT_HOST_KEY, "Password: \nPassword: \n", errors=[CONNECT_FAILED, RuntimeError("Bad Password")])
        outcome = self.collect(device)

        self.assertFalse(outcome.connected)
        self.assertIsNone(outcome.protocol)
        self.assertIn("under 1024 bits", outcome.error)
        self.assertIn("login over telnet failed too", outcome.error)
        self.assertIn("Bad Password", outcome.error)
        self.assertEqual(device.connections["cli"]["protocol"], "ssh")
        self.assertNotIn("port", device.connections["cli"])

    def test_an_algorithm_this_client_cannot_speak_also_falls_back(self):
        self.client_algorithms.return_value = {"kex": ("curve25519-sha256",)}
        device = self.device(KEX_REFUSED, "sw-1#\n", errors=[CONNECT_FAILED, None])
        outcome = self.collect(device)

        self.assertEqual(outcome.protocol, "telnet")
        self.assertTrue(outcome.connected)


if __name__ == "__main__":
    unittest.main()
