"""WS3: the testbed an export carries, with every secret in it replaced.

A hand-written testbed keeps its secrets wherever its author put them: under
a key of any name (`pwd`, `tacacs_key`, `authKey`, a `passwords:` mapping),
inside a command line or a URL, behind a pyATS %{...} reference, as a number
YAML read as one and aliased elsewhere, or as an %ENC{...} value under no
secret's key at all. These tests hold the redactor to each, and to what it
must keep for the owner to read: usernames, addresses, the OS and platform,
%ENV and %ASK references, and the ssh_options a login needed.

The literals are made up for these tests, the devices are the demo
network's and the addresses are documentation addresses.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

import yaml

from tests.test_collector_export import SNAPSHOT_ID, ExportFixture, contents, listed, rebuild
from netstate import export
from netstate.collector import REDACTION_MARKER

LITERAL = "Wq9-Probe-Lit-55"
DEVICE = "devices:\n  rbt-ald-pe1:\n    os: iosxr\n    platform: ASR-9901\n"
# The shape of the ssh_options DiscoNet writes into a testbed (testbedgen's
# legacy options, and what the collector's finalize adds after an algorithm
# negotiation): no secret in it, and the device-output rules once read its
# `sha1 -o ...` as an SNMPv3 `sha1 <key>`.
SSH_OPTIONS = (
    "-o KexAlgorithms=+diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1 "
    "-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa "
    "-o Ciphers=+aes128-cbc,3des-cbc -o MACs=+hmac-sha1"
)


def redacted(text: str) -> tuple[dict, int, list[str]]:
    """The tree export would write for a testbed's text, how many values it replaced, and its warnings."""
    warnings: list[str] = []
    tree, count = export.redact_testbed(yaml.safe_load(text), warnings)
    return tree, count, warnings


def written(tree: dict) -> str:
    return export.testbed_text(tree, SNAPSHOT_ID)


class AKeyIsASecretByItsWords(unittest.TestCase):
    def test_every_key_name_a_hand_written_testbed_keeps_a_secret_under_is_replaced(self):
        names = (
            "password", "enable_password", "pwd", "passwd", "pass", "pw", "psk", "passcode", "passphrase",
            "api_key", "tacacs_key", "radius_key", "snmp_key", "priv_key", "privkey", "ssh_key", "auth_key",
            "snmp_v3_auth_key", "pre_shared_key", "pre-shared-key", "key", "pin", "otp", "bearer", "token",
            "api_token", "secret", "enable_secret", "snmp_community", "ssh_private_key", "adminpw", "loginpass",
            "authKey", "apiKey", "APIKey", "snmpV3AuthKey", "x-api-key", "PIN", "Bearer", "pinCode", "otpSeed",
            "pskValue",
            "passwords", "pins", "keys", "tokens", "communities", "secrets",
        )
        for name in names:
            with self.subTest(key=name):
                tree, count, _warnings = redacted(DEVICE + f"    custom:\n      {name}: {LITERAL}\n")
                self.assertEqual(tree["devices"]["rbt-ald-pe1"]["custom"][name], REDACTION_MARKER)
                self.assertEqual(count, 1)
                self.assertNotIn(LITERAL, written(tree))

    def test_a_credential_set_under_any_key_name_keeps_its_username_and_loses_its_secret(self):
        tree, count, _warnings = redacted(
            DEVICE + f"    credentials:\n      default:\n        username: netops\n        pwd: {LITERAL}\n"
        )
        self.assertEqual(tree["devices"]["rbt-ald-pe1"]["credentials"]["default"],
                         {"username": "netops", "pwd": REDACTION_MARKER})
        self.assertEqual(count, 1)

    def test_usernames_addresses_the_os_platform_and_references_are_kept(self):
        text = (
            "testbed:\n  name: riverbend\n  credentials:\n    default:\n      username: netops\n"
            "      password: '%ENV{DISCONET_PASSWORD}'\n"
            "devices:\n  rbt-bht-p2:\n    os: junos\n    platform: MX204\n    type: router\n"
            "    credentials:\n      default:\n        user: jumpuser\n        login: netops\n"
            "        password: '%ASK{}'\n"
            "    connections:\n      cli:\n        protocol: ssh\n        ip: 198.51.100.12\n        port: 22\n"
        )
        tree, count, _warnings = redacted(text)
        self.assertEqual(tree, yaml.safe_load(text))
        self.assertEqual(count, 0)

    def test_a_mapping_or_list_under_a_secret_keeps_its_shape_and_every_value_but_a_reference_goes(self):
        tree, count, _warnings = redacted(
            "testbed:\n  passwords:\n    tacacs: '%ENV{TACACS_PASSWORD}'\n    enable: Enable-Probe-2207\n"
            "    line: [Line-Probe-3307, 482193, null, '']\n"
        )
        self.assertEqual(tree["testbed"]["passwords"], {
            "tacacs": "%ENV{TACACS_PASSWORD}", "enable": REDACTION_MARKER,
            "line": [REDACTION_MARKER, REDACTION_MARKER, None, ""],
        })
        self.assertEqual(count, 3)

    def test_an_encoded_secret_is_replaced_under_whatever_key_it_stands(self):
        tree, count, _warnings = redacted(
            DEVICE + "    custom:\n      jump_login: '%ENC{gAAAAABprobeEncodedValue}'\n"
            "      hops: [plain, 'via %ENC{gAAAAABprobeEncodedValue}']\n"
        )
        custom = tree["devices"]["rbt-ald-pe1"]["custom"]
        self.assertEqual(custom, {"jump_login": REDACTION_MARKER, "hops": ["plain", REDACTION_MARKER]})
        self.assertEqual(count, 2)


class AReferenceUnderASecretTakesWhatItNames(unittest.TestCase):
    def test_the_value_a_reference_names_is_replaced_and_swept_from_everywhere_else(self):
        tree, count, warnings = redacted(
            f"testbed:\n  name: riverbend\n  custom:\n    lab_login: {LITERAL}\n"
            "  credentials:\n    default:\n      username: netops\n      password: '%{testbed.custom.lab_login}'\n"
            "devices:\n  rbt-ald-pe1:\n    os: iosxr\n    credentials:\n      default:\n"
            "        password: '%{devices.rbt-bht-p2.custom.console}'\n"
            f"    custom:\n      note: 'the lab login is {LITERAL}'\n"
            "  rbt-bht-p2:\n    os: junos\n    custom:\n      console: Console-Probe-7731\n"
        )
        self.assertEqual(tree["testbed"]["custom"]["lab_login"], REDACTION_MARKER)
        self.assertEqual(tree["testbed"]["credentials"]["default"]["password"], REDACTION_MARKER)
        self.assertEqual(tree["devices"]["rbt-bht-p2"]["custom"]["console"], REDACTION_MARKER)
        self.assertEqual(tree["devices"]["rbt-ald-pe1"]["custom"]["note"], f"the lab login is {REDACTION_MARKER}")
        self.assertEqual(count, 5)
        self.assertEqual(warnings, [])
        self.assertNotIn(LITERAL, written(tree))
        self.assertNotIn("Console-Probe-7731", written(tree))

    def test_a_reference_to_a_reference_is_followed_and_a_loop_of_them_ends(self):
        tree, _count, _warnings = redacted(
            f"testbed:\n  custom:\n    first: '%{{testbed.custom.second}}'\n    second: {LITERAL}\n"
            "    loop_a: '%{testbed.custom.loop_b}'\n    loop_b: '%{testbed.custom.loop_a}'\n"
            "  credentials:\n    default:\n      password: '%{testbed.custom.first}'\n"
            "    enable:\n      password: '%{testbed.custom.loop_a}'\n"
        )
        self.assertNotIn(LITERAL, written(tree))
        self.assertEqual(tree["testbed"]["custom"]["second"], REDACTION_MARKER)

    def test_a_reference_that_names_nothing_in_the_file_is_replaced_and_warned_about(self):
        tree, count, warnings = redacted(
            DEVICE + "    credentials:\n      default:\n        password: '%{self.custom.lab_login}'\n"
        )
        self.assertEqual(tree["devices"]["rbt-ald-pe1"]["credentials"]["default"]["password"], REDACTION_MARKER)
        self.assertEqual(count, 1)
        self.assertEqual(len(warnings), 1)
        self.assertIn("%{self.custom.lab_login}, which names no value in the testbed itself", warnings[0])
        self.assertIn("devices.rbt-ald-pe1.credentials.default.password", warnings[0])


class APasswordInsideAStringIsReplaced(unittest.TestCase):
    def test_sshpass_in_a_command_a_proxy_command_and_a_url_lose_their_password_and_keep_the_rest(self):
        tree, count, _warnings = redacted(
            DEVICE + "    connections:\n      cli:\n        protocol: ssh\n        ip: 192.0.2.11\n"
            f"        command: sshpass -p {LITERAL} ssh -p 2222 ops@192.0.2.11\n"
            f"        ssh_options: \"{SSH_OPTIONS} -o ProxyCommand='sshpass -p{LITERAL} ssh -W %h:%p "
            f"ops@192.0.2.50'\"\n"
            f"        proxy: http://ops:{LITERAL}@192.0.2.60:8080/\n"
            f"        arguments: --password={LITERAL} --passive --pass '{LITERAL}'\n"
            f"    custom:\n      backup_url: scp://ops:{LITERAL}@192.0.2.5/cfg/\n"
            f"      note: the console password {LITERAL}\n"
        )
        cli = tree["devices"]["rbt-ald-pe1"]["connections"]["cli"]
        self.assertEqual(cli["command"], f"sshpass -p {REDACTION_MARKER} ssh -p 2222 ops@192.0.2.11")
        self.assertEqual(cli["ssh_options"], f"{SSH_OPTIONS} -o ProxyCommand='sshpass -p{REDACTION_MARKER} "
                                             f"ssh -W %h:%p ops@192.0.2.50'")
        self.assertEqual(cli["proxy"], f"http://{REDACTION_MARKER}@192.0.2.60:8080/")
        self.assertEqual(cli["arguments"], f"--password={REDACTION_MARKER} --passive --pass '{REDACTION_MARKER}'")
        custom = tree["devices"]["rbt-ald-pe1"]["custom"]
        self.assertEqual(custom["backup_url"], f"scp://{REDACTION_MARKER}@192.0.2.5/cfg/")
        self.assertEqual(custom["note"], f"the console password {REDACTION_MARKER}")
        self.assertEqual(count, 7)
        self.assertNotIn(LITERAL, written(tree))
        # What export wrote has nothing left to replace, which is what verify checks.
        self.assertEqual(export.redact_testbed(yaml.safe_load(written(tree)))[1], 0)

    def test_the_ssh_options_a_login_needed_are_kept_whole(self):
        text = DEVICE + f"    connections:\n      cli:\n        ssh_options: '{SSH_OPTIONS}'\n"
        tree, count, _warnings = redacted(text)
        self.assertEqual(tree["devices"]["rbt-ald-pe1"]["connections"]["cli"]["ssh_options"], SSH_OPTIONS)
        self.assertEqual(count, 0)

    def test_a_login_prompts_pattern_is_kept_as_written_and_its_answer_replaced(self):
        tree, count, _warnings = redacted(
            DEVICE + "    custom:\n      login_prompts:\n"
            "        - pattern: '(?i)token code:\\s*'\n          response: Token-Probe-4410\n"
        )
        self.assertEqual(tree["devices"]["rbt-ald-pe1"]["custom"]["login_prompts"],
                         [{"pattern": "(?i)token code:\\s*", "response": REDACTION_MARKER}])
        self.assertEqual(count, 1)


class TheSweepFindsALiteralAsANumberToo(unittest.TestCase):
    def test_a_numeric_secret_aliased_or_repeated_elsewhere_is_replaced_there(self):
        cases = {
            "an alias of the password elsewhere":
                "    credentials:\n      default:\n        password: &pin 73915824\n"
                "    custom:\n      console_pin_hint: *pin\n      note: dial 73915824\n",
            "an anchor elsewhere aliased under the password":
                "    custom:\n      console: &c 73915824\n"
                "    credentials:\n      default:\n        password: *c\n",
            "the number written out again":
                "    credentials:\n      default:\n        password: 73915824\n    custom:\n      label: 73915824\n",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                tree, _count, _warnings = redacted(DEVICE + body)
                self.assertNotIn("73915824", written(tree))

    def test_a_block_scalar_password_is_swept_without_its_newline(self):
        tree, count, _warnings = redacted(
            DEVICE + f"    credentials:\n      default:\n        password: |\n          {LITERAL}\n"
            f"    connections:\n      cli:\n        command: x {LITERAL} y\n"
        )
        self.assertNotIn(LITERAL, written(tree))
        self.assertEqual(count, 2)

    def test_a_short_number_or_a_flag_is_not_swept(self):
        tree, _count, _warnings = redacted(
            DEVICE + "    credentials:\n      default:\n        password: 482\n"
            "    connections:\n      cli:\n        port: 482\n        check: true\n"
        )
        self.assertEqual(tree["devices"]["rbt-ald-pe1"]["connections"]["cli"], {"port": 482, "check": True})


class TheTestbedIsReadSafely(ExportFixture):
    def test_a_testbed_that_does_not_parse_is_refused_by_line_and_column_without_its_text(self):
        cases = {
            "a colon in the password": f"testbed:\n  credentials:\n    default:\n      password: {LITERAL}: x\n",
            "a quote left open": f"testbed:\n  credentials:\n    default:\n      password: \"{LITERAL}\n"
                                 "      username: netops\n",
            "a tab": f"testbed:\n  credentials:\n\tdefault:\n      password: {LITERAL}\n",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.testbed.write_text(text, encoding="utf-8")
                with self.assertRaises(export.ExportRefused) as caught:
                    self.exported()
                said = str(caught.exception)
                self.assertNotIn(LITERAL, said)
                # Nor in the YAML error it was raised from, which a traceback or a log would print:
                # read from a stream, PyYAML keeps no copy of the text to quote.
                self.assertNotIn(LITERAL, str(caught.exception.__cause__))
                self.assertRegex(said, r"could not be read as YAML: .+, at line \d+, column \d+$")
                self.assertEqual(list(self.out.iterdir()), [])

    def test_a_reference_that_names_nothing_is_warned_about_by_export(self):
        self.testbed.write_text(
            self.testbed.read_text(encoding="utf-8").replace(
                "password: \"%ENV{DISCONET_PASSWORD}\"", "password: \"%{self.custom.lab_login}\""),
            encoding="utf-8",
        )
        result = self.exported()
        self.assertTrue([w for w in result.warnings if "%{self.custom.lab_login}" in w], result.warnings)
        self.assertTrue(export.verify_archive(result.path).ok)

    def test_a_testbed_of_aliases_that_expand_past_the_limit_is_refused_at_export_and_failed_by_verify(self):
        bomb = "a: &a [x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a]\n" \
               "c: &c [*b, *b, *b, *b, *b, *b, *b, *b]\nd: [*c, *c, *c, *c, *c, *c, *c, *c]\n"
        good = self.exported().path
        self.testbed.write_text(bomb + "devices:\n  rbt-ald-pe1:\n    os: iosxr\n", encoding="utf-8")
        with mock.patch.object(export, "TESTBED_VALUE_LIMIT", 1000):
            with self.assertRaises(export.OversizedTestbed) as caught:
                self.exported("bomb.export.tar.gz")
            self.assertIn("more than 1,000 values once its YAML aliases are followed", str(caught.exception))
            target = f"{SNAPSHOT_ID}/testbed.yaml"
            bad = self.out / "bomb-inside.export.tar.gz"

            def change(members, document):
                members[target] = bomb.encode("utf-8")
                listed(document, target, members[target])

            rebuild(good, bad, change)
            report = export.verify_archive(bad)
        self.assertFalse(report.ok)
        self.assertTrue([p for p in report.problems if p.startswith(f"{target} holds more than 1,000 values")],
                        report.problems)

    def test_every_secret_of_a_hand_written_testbed_stays_out_of_the_archive_and_verify_agrees(self):
        self.testbed.write_text(
            "testbed:\n  name: fixture\n"
            f"  custom:\n    lab_login: {LITERAL}\n    tacacs_key: Tacacs-Probe-1188\n"
            "  credentials:\n    default:\n      username: netops\n      password: '%{testbed.custom.lab_login}'\n"
            "devices:\n"
            "  rbt-ald-pe1:\n    os: iosxr\n    platform: ASR-9901\n"
            "    credentials:\n      default:\n        username: netops\n        pwd: &pin 73915824\n"
            "    connections:\n      cli:\n        protocol: ssh\n        ip: 192.0.2.11\n"
            "        command: sshpass -p Jump-Probe-6604 ssh ops@192.0.2.50\n"
            "    custom:\n      authKey: Auth-Probe-5510\n      console_pin_hint: *pin\n"
            "      jump: '%ENC{gAAAAABprobeEncodedValue}'\n"
            "  rbt-bht-p2:\n    os: junos\n    connections:\n      cli:\n        protocol: ssh\n"
            "        ip: 198.51.100.12\n        proxy: http://ops:Proxy-Probe-3307@192.0.2.60:8080/\n",
            encoding="utf-8",
        )
        result = self.exported()
        archived = contents(result.path)
        for secret in (LITERAL, "Tacacs-Probe-1188", "73915824", "Jump-Probe-6604", "Auth-Probe-5510",
                       "gAAAAABprobeEncodedValue", "Proxy-Probe-3307"):
            for name, data in archived.items():
                self.assertNotIn(secret.encode(), data, f"{secret} in {name}")
        tree = yaml.safe_load(archived[f"{SNAPSHOT_ID}/testbed.yaml"])
        self.assertEqual(tree["devices"]["rbt-ald-pe1"]["credentials"]["default"]["username"], "netops")
        self.assertEqual(tree["devices"]["rbt-bht-p2"]["connections"]["cli"]["ip"], "198.51.100.12")
        document = json.loads(archived[f"{SNAPSHOT_ID}/export-manifest.json"])
        self.assertEqual(document["testbed"]["redacted_values"], result.redacted_values)
        self.assertEqual(result.redacted_values, 9)
        report = export.verify_archive(result.path)
        self.assertTrue(report.ok, report.problems)


if __name__ == "__main__":
    unittest.main()
