"""The read-only guarantee: nothing off the allowlist can reach a device."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from netstate.collector import (
    ALL_FEATURES,
    DEFAULT_COMMANDS_FILE,
    CollectionError,
    CommandNotAllowed,
    CommandPolicy,
    slugify,
)


class ShippedAllowlistTestCase(unittest.TestCase):
    """The allowlist DiscoNet actually ships with."""

    @classmethod
    def setUpClass(cls):
        cls.policy = CommandPolicy.load(DEFAULT_COMMANDS_FILE)

    def test_covers_every_registered_platform(self):
        from netstate.platforms import platform_keys

        self.assertEqual(set(self.policy.os_names), set(platform_keys()))

    def test_the_configuration_is_raw_only_on_every_platform(self):
        from netstate.platforms import platform_for

        for os_name in self.policy.os_names:
            plan = self.policy.plan_for(os_name)
            config = platform_for(os_name).config_command
            self.assertEqual(plan.raw_only, (config,))
            self.assertNotIn(config, plan.parse)

    def test_allowlisted_command_passes_the_gate(self):
        self.policy.assert_allowed("iosxe", "show ip ospf neighbor")

    def test_whitespace_and_case_are_normalised(self):
        self.policy.assert_allowed("iosxe", "  SHOW   IP  BGP   summary ")

    def test_read_only_command_not_on_the_list_is_still_refused(self):
        # A harmless show command still has to be listed to be sent.
        with self.assertRaises(CommandNotAllowed):
            self.policy.assert_allowed("iosxe", "show clock")

    def test_platform_specific_command_is_not_allowed_on_the_other_platform(self):
        self.policy.assert_allowed("iosxe", "show ip interface brief")
        with self.assertRaises(CommandNotAllowed):
            self.policy.assert_allowed("iosxr", "show ip interface brief")

    def test_unknown_os_is_refused(self):
        with self.assertRaises(CollectionError):
            self.policy.assert_allowed("eos", "show version")


class PolicyValidationTestCase(unittest.TestCase):
    """A bad commands.yaml must fail at load time, before any connection."""

    def policy(self, commands):
        return CommandPolicy({"iosxe": {"parse": commands}})

    def test_configuration_commands_are_refused(self):
        for command in (
            "configure terminal",
            "conf t",
            "write memory",
            "reload",
            "clear ip bgp *",
            "copy running-config startup-config",
            "debug ip ospf",
            "no shutdown",
            "commit",
            "license install foo",
        ):
            with self.subTest(command=command), self.assertRaises(CommandNotAllowed):
                self.policy([command])

    def test_shell_metacharacters_are_refused(self):
        for command in ("show version ; reload", "show version | tclsh", "show ver && reload"):
            with self.subTest(command=command), self.assertRaises(CommandNotAllowed):
                self.policy([command])

    def test_non_show_command_is_refused(self):
        with self.assertRaises(CommandNotAllowed):
            self.policy(["ping 10.0.0.1"])

    def test_control_characters_are_refused(self):
        """BUG-249: ^U and ^W erase what was typed before them, so 'show version^Uwrite memory' sends 'write memory'."""
        for command in (
            "show version\x15write memory",
            "show version\x17\x17write memory",
            "show version\x1b[A",
            "show version\x00",
            "show versi\u00f3n",
        ):
            with self.subTest(command=command), self.assertRaises(CommandNotAllowed):
                self.policy([command])

    def test_a_tab_between_words_is_only_whitespace(self):
        # Collapsed to one space before anything is sent, like any other run of whitespace.
        self.assertIn("show version", self.policy(["show\tversion"]).allowed_commands("iosxe"))

    def test_empty_and_non_string_entries_are_refused(self):
        for command in ("", "   ", None, 42, ["show", "version"]):
            with self.subTest(command=command), self.assertRaises(CommandNotAllowed):
                self.policy([command])

    def test_running_config_is_not_confused_with_a_config_verb(self):
        # "running-config" is one token, so the "config" denylist entry must not
        # fire on it.
        policy = CommandPolicy({"iosxe": {"raw_only": ["show running-config"]}})
        policy.assert_allowed("iosxe", "show running-config")

    def test_os_with_no_commands_is_refused(self):
        with self.assertRaises(CollectionError):
            CommandPolicy({"iosxe": {"parse": [], "raw_only": []}})

    def test_empty_file_is_refused(self):
        with self.assertRaises(CollectionError):
            CommandPolicy({})

    def test_missing_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CollectionError):
                CommandPolicy.load(Path(tmp) / "nope.yaml")

    def test_a_bad_file_on_disk_is_refused_at_load_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "commands.yaml"
            path.write_text(
                "iosxe:\n  parse:\n    - show version\n    - configure terminal\n",
                encoding="utf-8",
            )
            with self.assertRaises(CommandNotAllowed):
                CommandPolicy.load(path)


class SlugifyTestCase(unittest.TestCase):
    def test_commands_become_filesystem_safe_names(self):
        self.assertEqual(slugify("show ip interface brief"), "show_ip_interface_brief")
        self.assertEqual(slugify("show running-config"), "show_running_config")
        self.assertEqual(slugify("show cdp neighbors detail"), "show_cdp_neighbors_detail")


class FeatureGroupTestCase(unittest.TestCase):
    """Optional groups narrow what is sent; they never widen it."""

    SPEC = {
        "iosxe": {
            "parse": ["show version"],
            "raw_only": ["show running-config"],
            "features": {
                "ospf": {"parse": ["show ip ospf neighbor"]},
                "isis": {"parse": ["show isis neighbors"]},
                "l3vpn": {"parse": ["show vrf detail"]},
            },
        }
    }

    def policy(self, spec=None):
        return CommandPolicy(spec or self.SPEC)

    def test_a_feature_command_is_allowlisted_whether_or_not_it_is_selected(self):
        # The allowlist is the file. Selection decides what leaves the tool.
        policy = self.policy()
        self.assertEqual(
            policy.assert_allowed("iosxe", "show isis neighbors"), "show isis neighbors"
        )

    def test_selecting_nothing_still_collects_the_base_commands(self):
        plan = self.policy().plan_for("iosxe")
        self.assertEqual(plan.selected_parse([]), ("show version",))

    def test_selecting_a_group_adds_exactly_that_group(self):
        plan = self.policy().plan_for("iosxe")
        self.assertEqual(
            plan.selected_parse(["ospf"]), ("show version", "show ip ospf neighbor")
        )

    def test_no_selection_at_all_means_everything_rather_than_nothing(self):
        # A run with no answer collects everything: quietly skipping a protocol
        # would be a decision the engineer never made.
        plan = self.policy().plan_for("iosxe")
        self.assertEqual(len(plan.selected_parse(None)), 4)

    def test_the_order_of_a_plan_does_not_depend_on_the_order_of_the_selection(self):
        plan = self.policy().plan_for("iosxe")
        self.assertEqual(plan.selected_parse(["isis", "ospf"]), plan.selected_parse(["ospf", "isis"]))

    def test_a_feature_command_is_held_to_the_same_rule_as_every_other(self):
        with self.assertRaises(CommandNotAllowed):
            CommandPolicy({"iosxe": {"parse": ["show version"],
                                     "features": {"ospf": {"parse": ["configure terminal"]}}}})

    def test_an_unknown_feature_name_is_refused_at_load_time(self):
        # A group nothing can ever ask for would silently never be collected.
        with self.assertRaises(CollectionError) as caught:
            CommandPolicy({"iosxe": {"parse": ["show version"],
                                     "features": {"quantum": {"parse": ["show version"]}}}})
        self.assertIn("quantum", str(caught.exception))

    def test_the_features_on_offer_come_from_the_allowlist_not_from_a_fixed_list(self):
        self.assertEqual(self.policy().available_features, ("ospf", "isis", "l3vpn"))

    def test_the_real_allowlist_offers_every_documented_feature_on_both_platforms(self):
        policy = CommandPolicy.load()
        self.assertEqual(set(policy.available_features), set(ALL_FEATURES))
        # `security` is the firewall vocabulary: offered where a firewall
        # answers it (ASA, and Junos for the SRX), never on a router.
        # `switching` is the access layer: IOS-XR has no VLAN switching to
        # read and is the one router platform without it.
        self.assertEqual(set(policy.features_for("iosxe")), set(ALL_FEATURES) - {"security"})
        self.assertEqual(set(policy.features_for("iosxr")), set(ALL_FEATURES) - {"security", "switching"})
        self.assertEqual(set(policy.features_for("ios")), set(ALL_FEATURES) - {"security"})
        self.assertIn("security", policy.features_for("asa"))
        self.assertIn("security", policy.features_for("junos"))

    def test_the_ptp_domain_is_a_literal_string_rather_than_a_rendered_one(self):
        # A rendered command is a second exception beside ping. The domain is
        # lab-specific, so it is changed by editing commands.yaml.
        commands = CommandPolicy.load().plan_for("iosxe").feature_commands["ptp"]
        self.assertIn("show ptp clock running domain 44", commands)
        for command in commands:
            self.assertNotIn("{", command)


class MulticastFeatureTests(unittest.TestCase):
    """Multicast is one selection covering both the global table and MVPN.

    Asked as one box because it is one question: a core that carries a
    customer's multicast carries it over the same links its own PIM adjacencies
    are formed on, and a document describing one without the other explains
    half a path.
    """

    def setUp(self) -> None:
        from netstate.collector import CommandPolicy, DEFAULT_COMMANDS_FILE

        self.policy = CommandPolicy.load(DEFAULT_COMMANDS_FILE)

    def test_multicast_is_one_feature_not_two(self):
        from netstate.collector import PROTOCOL_FEATURES, SERVICE_FEATURES

        self.assertIn("multicast", PROTOCOL_FEATURES)
        self.assertNotIn("mvpn", PROTOCOL_FEATURES + SERVICE_FEATURES)

    def test_both_platforms_offer_it(self):
        for os_name in ("iosxe", "iosxr"):
            with self.subTest(os=os_name):
                selected = self.policy.plan_for(os_name).selected_parse(["multicast"])
                self.assertTrue(any("pim" in command for command in selected))

    def test_the_global_table_and_the_mvpn_overlay_are_both_collected(self):
        for os_name, neighbour, mvpn in (
            ("iosxe", "show ip pim neighbor", "show ip pim mdt"),
            ("iosxr", "show pim neighbor", "show pim vrf all mdt cache"),
        ):
            with self.subTest(os=os_name):
                selected = self.policy.plan_for(os_name).selected_parse(["multicast"])
                self.assertIn(neighbour, selected)
                self.assertIn(mvpn, selected)

    def test_deselecting_it_sends_none_of_it(self):
        # The menu narrows what leaves the tool and can never widen it.
        selected = self.policy.plan_for("iosxr").selected_parse(["ospf"])
        self.assertFalse([command for command in selected if "pim" in command])

    def test_every_multicast_command_is_a_show_command(self):
        # The allowlist rule, checked here as well because a feature block is
        # exactly where a non-show command would be easiest to slip in.
        for os_name in ("iosxe", "iosxr"):
            for command in self.policy.plan_for(os_name).selected_parse(["multicast"]):
                self.assertTrue(command.startswith("show "), command)

    def test_it_has_a_label_for_the_menu_and_the_document(self):
        from netstate.collector import feature_label

        self.assertEqual(feature_label("multicast"), "Multicast and MVPN")


if __name__ == "__main__":
    unittest.main()
