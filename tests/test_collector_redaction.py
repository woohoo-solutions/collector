"""Credential material must never reach disk."""

from __future__ import annotations

import re
import unittest

from netstate.collector import REDACTION_MARKER, redact

RUNNING_CONFIG = """\
Building configuration...
!
hostname R1
!
enable secret 5 $1$abcd$KJhgFDsaQwErTy123
username admin privilege 15 password 0 LabPassw0rd
!
service password-encryption
!
interface GigabitEthernet1
 description CORE_LINK_TO_R2
 ip address 10.0.0.1 255.255.255.252
!
router ospf 1
 area 0 authentication message-digest
 ip ospf message-digest-key 1 md5 SuperSecret99
!
snmp-server community public RO
snmp-server community privateRW RW
!
crypto key generate rsa modulus 2048
!
end
"""


class RedactionTestCase(unittest.TestCase):
    def test_secrets_are_stripped(self):
        out, _ = redact(RUNNING_CONFIG)
        for secret in (
            "$1$abcd$KJhgFDsaQwErTy123",
            "LabPassw0rd",
            "SuperSecret99",
            "public",
            "privateRW",
        ):
            self.assertNotIn(secret, out)

    def test_the_keyword_stays_so_the_excerpt_still_reads(self):
        out, _ = redact(RUNNING_CONFIG)
        self.assertIn("enable secret " + REDACTION_MARKER, out)
        self.assertIn("snmp-server community " + REDACTION_MARKER, out)

    def test_redacted_line_count_is_reported(self):
        _, changed = redact(RUNNING_CONFIG)
        self.assertEqual(changed, 6)

    def test_operational_facts_survive(self):
        out, _ = redact(RUNNING_CONFIG)
        for fact in (
            "hostname R1",
            "interface GigabitEthernet1",
            " description CORE_LINK_TO_R2",
            " ip address 10.0.0.1 255.255.255.252",
            "router ospf 1",
        ):
            self.assertIn(fact, out)

    def test_line_count_is_preserved(self):
        out, _ = redact(RUNNING_CONFIG)
        self.assertEqual(len(out.splitlines()), len(RUNNING_CONFIG.splitlines()))

    def test_keyword_with_no_value_is_left_alone(self):
        out, changed = redact("service password-encryption\n")
        self.assertEqual(changed, 0)
        self.assertEqual(out, "service password-encryption")

    def test_redaction_is_case_insensitive(self):
        out, changed = redact("SNMP-SERVER COMMUNITY Public RO")
        self.assertNotIn("Public", out)
        self.assertEqual(changed, 1)

    def test_empty_input(self):
        self.assertEqual(redact(""), ("", 0))


class AnXrHsrpStringIsASecretWithNoKeywordBeforeIt(unittest.TestCase):
    """BUG-173: IOS-XR writes an HSRP group's plain-text string as a bare `authentication <string>`."""

    XR_HSRP = (
        "router hsrp\n"
        " interface GigabitEthernet0/0/0/1\n"
        "  address-family ipv4\n"
        "   hsrp 1\n"
        "    authentication XrHsrp1\n"
        "    priority 110\n"
        "    address 10.0.0.1\n"
    )

    def test_the_string_goes_and_the_group_stays(self):
        out, changed = redact(self.XR_HSRP)
        self.assertNotIn("XrHsrp1", out)
        self.assertIn(f"    authentication {REDACTION_MARKER}\n", out)
        self.assertIn("    address 10.0.0.1", out)
        self.assertEqual(changed, 1)

    def test_a_mode_written_the_same_way_is_not_a_secret(self):
        for line in (
            "   authentication message-digest",
            "   authentication null",
            " authentication open",
            " authentication periodic",
            " authentication certificate",
            "        authentication {",
            "   authentication",
            "   authentication message-digest keychain OSPF-KC",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_an_ike_policy_s_method_and_an_ssid_s_or_ospfv3_s_mode_are_kept(self):
        """F-14: the IKE method under `crypto isakmp policy` or `crypto ikev1 policy`, `shared` under a dot11 SSID, XR OSPFv3's `disable`."""
        for line in (
            " authentication pre-share",
            " authentication rsa-sig",
            " authentication rsa-encr",
            " authentication ecdsa-sig",
            " authentication crack",
            " authentication shared",
            "    authentication disable",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))
        self.assertEqual(redact(self.XR_HSRP)[1], 1)   # and the HSRP string still goes


class CommunityIsOnlyASecretWhereItIsSnmpTestCase(unittest.TestCase):
    """A BGP community is a route target's name, and redacting it leaves every
    policy-built VRF with no target to be read."""

    JUNOS = """\
snmp {
    community public {
        authorization read-only;
    }
    community s3cret;
}
policy-options {
    policy-statement L3VPN:NETX-IP:import {
        term 1 {
            from {
                protocol bgp;
                community Comm:RT:NETX-IP;
            }
            then accept;
        }
    }
    policy-statement L3VPN:NETX-IP:export {
        term 1 {
            then {
                community add Comm:RT:NETX-IP;
                accept;
            }
        }
    }
    community Comm:RT:NETX-IP members target:64512:1;
}
"""

    def test_a_junos_snmp_community_is_still_redacted_inside_its_block(self):
        out, _ = redact(self.JUNOS)
        self.assertNotIn("public", out)
        self.assertNotIn("s3cret", out)
        self.assertIn("    community " + REDACTION_MARKER + " {", out)

    def test_a_junos_policy_community_survives_with_its_target(self):
        out, changed = redact(self.JUNOS)
        self.assertIn("community Comm:RT:NETX-IP members target:64512:1;", out)
        self.assertIn("                community Comm:RT:NETX-IP;", out)
        self.assertIn("                community add Comm:RT:NETX-IP;", out)
        self.assertEqual(changed, 2)

    def test_the_block_tracking_closes_so_a_policy_after_snmp_is_not_taken_for_snmp(self):
        text = "snmp {\n    community public;\n}\ncommunity Comm:RT:X members target:1:1;\n"
        out, changed = redact(text)
        self.assertIn("community Comm:RT:X members target:1:1;", out)
        self.assertEqual(changed, 1)

    def test_an_ios_snmp_community_and_an_asa_host_community_are_still_redacted(self):
        out, _ = redact("snmp-server community public RO\nsnmp-server host inside 10.1.1.1 community topsecret version 2c\n")
        self.assertNotIn("public", out)
        self.assertNotIn("topsecret", out)

    def test_an_ios_community_list_and_a_set_community_survive(self):
        text = "ip community-list standard CUST permit 65000:100\nroute-map X permit 10\n set community 65000:100 additive\n"
        out, changed = redact(text)
        self.assertEqual(out, text.rstrip("\n"))
        self.assertEqual(changed, 0)


class AJunosWarningAfterABraceStillOpensTheBlock(unittest.TestCase):
    """BUG-217: Junos prints `## Warning: ...` after a deprecated statement's brace, and the brace still opens a block."""

    def test_an_snmp_block_opened_with_a_warning_still_redacts_its_communities(self):
        text = (
            "snmp { ## Warning: 'snmp' is deprecated\n"
            "    community public {\n"
            "        authorization read-only;\n"
            "    }\n"
            "}\n"
        )
        out, changed = redact(text)
        self.assertNotIn("public", out)
        self.assertIn("    community " + REDACTION_MARKER + " {", out)
        self.assertEqual(changed, 1)

    def test_a_community_opened_with_a_warning_keeps_its_brace_and_the_block_after_it_closes(self):
        text = (
            "snmp {\n"
            "    community public { ## Warning: 'community' is deprecated\n"
            "        authorization read-only;\n"
            "    }\n"
            "    community s3cret;\n"
            "}\n"
            "community Comm:RT:X members target:1:1;\n"
        )
        out, changed = redact(text)
        self.assertNotIn("public", out)
        self.assertNotIn("s3cret", out)
        self.assertIn("    community " + REDACTION_MARKER + " {", out)
        self.assertIn("community Comm:RT:X members target:1:1;", out)
        self.assertEqual(changed, 2)

    def test_a_block_with_a_warning_inside_snmp_does_not_close_snmp_early(self):
        text = "snmp {\n    v3 { ## Warning: 'v3' is deprecated\n        usm;\n    }\n    community s3cret;\n}\n"
        out, _ = redact(text)
        self.assertNotIn("s3cret", out)
        self.assertIn("    v3 { ## Warning: 'v3' is deprecated", out)


class LinesTheReviewFoundInClear(unittest.TestCase):
    """Realistic lines that passed the keyword list unchanged, and lines it took too much of."""

    SECRETS = {
        "standby 1 authentication text S3cretHSRP": "S3cretHSRP",
        "standby 1 authentication S3cretHSRP": "S3cretHSRP",
        "vrrp 1 authentication text VRRPTEXT": "VRRPTEXT",
        "glbp 1 authentication text GLBPTEXT": "GLBPTEXT",
        "    authentication text NXHSRP": "NXHSRP",
        "  text-authentication XRVRRP": "XRVRRP",
        " ip nhrp authentication NHRPKEY": "NHRPKEY",
        "  authentication mode hmac-sha-256 7 EIGRPKEY": "EIGRPKEY",
        " wpa-psk ascii 0 WIFIPASS": "WIFIPASS",
        "  key-octet-string 7 MACSECKEY": "MACSECKEY",
        '        cak "$9$abcJUNOS";': "$9$abcJUNOS",
        '        community-name "$9$abcCOMM";': "$9$abcCOMM",
        "snmp mib community-map PUBLICMAP context vrfA": "PUBLICMAP",
        " path scp://backup:B4ckupP4ss@10.0.0.5/$h-$t": "B4ckupP4ss",
        "snmp-server user admin network-admin auth sha-256 0xAUTHKEY priv aes-128 0xPRIVKEY localizedV2key": "0xAUTHKEY",
        '        authentication-key "$9$SECRET"; ## SECRET-DATA': "$9$SECRET",
        "vrrp 1 authentication md5 key-string MD5KEY": "MD5KEY",
    }

    def test_every_line_the_review_found_loses_its_secret(self):
        for line, secret in self.SECRETS.items():
            out, changed = redact(line)
            self.assertNotIn(secret, out, line)
            self.assertIn(REDACTION_MARKER, out, line)
            self.assertEqual(changed, 1, line)

    def test_the_ospfv3_ipsec_line_loses_both_keys(self):
        out, _ = redact(" ipv6 ospf encryption ipsec spi 256 esp 3des ESPKEY1 md5 MD5KEY2")
        self.assertNotIn("ESPKEY1", out)
        self.assertNotIn("MD5KEY2", out)
        self.assertIn("esp 3des", out)

    def test_an_aes_key_written_after_a_separate_size_loses_both_keys(self):
        """BUG-250: `esp aes-cbc 128 KEY` (IOS-XE) and `esp aes 192 clear KEY` (IOS-XR) kept the ESP key."""
        for line in (
            " ipv6 ospf encryption ipsec spi 256 esp aes-cbc 128 ESPKEY1 sha1 SHAKEY2",
            " ospfv3 encryption ipsec spi 256 esp aes-cbc 256 7 ESPKEY1 sha1 SHAKEY2",
            "  encryption ipsec spi 256 esp aes 192 clear ESPKEY1 sha1 clear SHAKEY2",
            "  encryption ipsec spi 256 esp aes clear ESPKEY1 md5 clear SHAKEY2",
            " ipv6 ospf encryption ipsec spi 256 esp aes-cbc-128 ESPKEY1 sha1 SHAKEY2",
        ):
            with self.subTest(line=line):
                out, changed = redact(line)
                self.assertNotIn("ESPKEY1", out)
                self.assertNotIn("SHAKEY2", out)
                self.assertIn("spi 256 esp aes", out)
                self.assertEqual(changed, 1)

    def test_an_all_digit_aes_key_is_not_taken_for_its_size(self):
        """BUG-250: the size is 128, 192 or 256 alone; a key made of digits is still the key."""
        out, _ = redact("  encryption ipsec spi 256 esp aes 1234567890123456 sha1 SHAKEY2")
        self.assertNotIn("1234567890123456", out)

    def test_the_url_keeps_its_host_and_path_and_loses_the_credentials(self):
        out, _ = redact(" path scp://backup:B4ckupP4ss@10.0.0.5/$h-$t")
        self.assertEqual(out, f" path scp://{REDACTION_MARKER}@10.0.0.5/$h-$t")
        self.assertEqual(redact(" path scp://10.0.0.5/$h-$t"), (" path scp://10.0.0.5/$h-$t", 0))

    def test_credentials_holding_an_at_sign_or_a_slash_go_whole(self):
        """BUG-251: the userinfo runs to the last '@' of the URL, so `p@ss` and `pa/ss` lose their tails too."""
        for url in (
            "scp://backup:p@ss@10.0.0.5/$h-$t",
            "scp://backup:pa/ss@10.0.0.5/$h-$t",
            "scp://backup@corp:B4ckupP4ss@10.0.0.5/$h-$t",
        ):
            with self.subTest(url=url):
                out, changed = redact(f" path {url}")
                self.assertEqual(out, f" path scp://{REDACTION_MARKER}@10.0.0.5/$h-$t")
                self.assertEqual(changed, 1)

    def test_each_url_on_a_line_loses_only_its_own_credentials(self):
        """BUG-251: the last '@' is the last of the URL, not of the line."""
        out, _ = redact("copy scp://a:p@ss@192.0.2.1/x ftp://b:q/r@192.0.2.2/y")
        self.assertEqual(out, f"copy scp://{REDACTION_MARKER}@192.0.2.1/x ftp://{REDACTION_MARKER}@192.0.2.2/y")

    def test_a_url_with_a_port_and_no_password_keeps_every_word(self):
        for line in (" path ftp://10.0.0.5:21/$h-$t", " path ftp://backup@10.0.0.5:21/$h-$t"):
            self.assertEqual(redact(line), (line, 0))

    def test_an_at_sign_in_the_path_after_a_host_and_port_is_no_userinfo(self):
        """F-34: `host:port/path@x` lost its host and port as if they were a user and a password."""
        for line in (
            " path tftp://10.0.0.1:69/cfg@site",
            " enrollment url http://ca.example.com:80/certsrv/mscep/mscep.dll@site",
            '                "ftp://10.0.0.1:21/backups@site";',
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_password_that_looks_like_a_port_still_goes_after_a_user_name(self):
        """F-34: only an address or a dotted name is read as a host before `:port/`; `admin` is a user."""
        for url in ("scp://admin:1234/x@10.0.0.1/cfg", "http://admin:8080/x@10.0.0.1/cfg"):
            with self.subTest(url=url):
                scheme = url.split("://")[0]
                self.assertEqual(redact(f" path {url}"), (f" path {scheme}://{REDACTION_MARKER}@10.0.0.1/cfg", 1))

    def test_a_dotted_user_with_a_password_that_looks_like_a_port_still_goes(self):
        """F-34's residue: `admin.ops:1234/` read as a host and its port, though a host follows the last `@`."""
        for line, kept in (
            ("copy scp://admin.ops:1234/x@10.0.0.1/file flash:", f"copy scp://{REDACTION_MARKER}@10.0.0.1/file flash:"),
            (" path scp://admin.ops:1234/x@backup.example.com/cfg", f" path scp://{REDACTION_MARKER}@backup.example.com/cfg"),
            (" path scp://admin.ops:1234/x@backup/cfg", f" path scp://{REDACTION_MARKER}@backup/cfg"),
            (" path scp://admin.ops:1234/x@10.0.0.1:22/cfg", f" path scp://{REDACTION_MARKER}@10.0.0.1:22/cfg"),
            (" path scp://admin.ops:1234/x@[2001:db8::1]/cfg", f" path scp://{REDACTION_MARKER}@[2001:db8::1]/cfg"),
            # A host and port with a path ending in `@` and an address is
            # read as credentials: the line cannot say which, and this is the
            # way to be wrong that leaks nothing.
            (" path scp://10.0.0.9:1234/x@10.0.0.1", f" path scp://{REDACTION_MARKER}@10.0.0.1"),
            ('    "scp://admin.ops:1234/x@10.0.0.1";', f'    "scp://{REDACTION_MARKER}@10.0.0.1";'),
            (" path scp://admin.ops:1234/x@y@10.0.0.1/cfg", f" path scp://{REDACTION_MARKER}@10.0.0.1/cfg"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (kept, 1))

    def test_a_junos_line_marked_secret_data_is_redacted_whatever_its_keyword(self):
        out, changed = redact('    some-new-statement "value nobody listed"; ## SECRET-DATA')
        self.assertNotIn("nobody", out)
        self.assertEqual(changed, 1)

    def test_lines_that_carry_no_secret_keep_every_word(self):
        for line in (
            "key chain ISIS-AUTH",
            "key chain ISIS-AUTH\n key 1",
            "mka pre-shared-key key-chain MKA",
            "ip rip authentication mode text",
            "ip http authentication local",
            "standby 1 authentication md5 key-chain HSRP-CHAIN",
            "neighbor 10.255.0.4 send-community extended",
            "community SNMP-MGMT-RT members target:65000:161;",
            "from community SNMP-MGMT-RT;",
            "ip community-list standard X permit 65000:1",
            "set community 65000:100",
            " 1 BGP extended community entries using 40 bytes of memory",
            "snmp-server enable traps",
        ):
            self.assertEqual(redact(line), (line, 0), line)

    def test_the_isakmp_key_goes_and_the_peer_address_stays(self):
        out, _ = redact("crypto isakmp key MyIsakmpKey address 192.0.2.7")
        self.assertNotIn("MyIsakmpKey", out)
        self.assertIn("address 192.0.2.7", out)

    def test_the_key_id_stays_and_the_key_string_goes_inside_a_chain(self):
        out, changed = redact("key chain ISIS-AUTH\n key 1\n  key-string 7 0822455D0A16\n  cryptographic-algorithm hmac-sha-256\n")
        self.assertIn("key chain ISIS-AUTH", out)
        self.assertIn(" key 1\n", out)
        self.assertNotIn("0822455D0A16", out)
        self.assertEqual(changed, 1)

    def test_the_snmp_communities_are_still_redacted(self):
        for line in (
            "snmp-server community S3cret RO",
            "snmp-server community S3cret RO SystemOwner",
            "snmp-server host 192.0.2.9 version 2c S3cret",
        ):
            out, changed = redact(line)
            self.assertNotIn("S3cret", out, line)
            self.assertEqual(changed, 1, line)
        out, _ = redact("snmp {\n    community S3cret {\n        authorization read-only;\n    }\n}\n")
        self.assertNotIn("S3cret", out)


class AKeyNumberIsAnIdentifierOnlyUnderAKeyChain(unittest.TestCase):
    """BUG-063: a bare `key <digits>` numbers a key only inside `key chain`; elsewhere it is the key."""

    def test_a_numeric_radius_or_tacacs_key_is_redacted(self):
        for config, secret in (
            ("radius server RAD-1\n address ipv4 192.0.2.5 auth-port 1812 acct-port 1813\n key 12345678\n", "12345678"),
            ("tacacs server TAC-1\n address ipv4 192.0.2.6\n key 4711\n", "4711"),
            ("radius-server host 192.0.2.5 auth-port 1645 acct-port 1646\n key 90210\n", "90210"),
        ):
            with self.subTest(config=config):
                out, changed = redact(config)
                self.assertNotIn(secret, out)
                self.assertEqual(changed, 1)

    def test_the_key_number_under_a_key_chain_stays(self):
        for config in (
            "key chain ISIS-AUTH\n key 1\n  key-string 7 0822455D0A16\n",
            "key chain MKA-KC macsec\n key 1000\n  cryptographic-algorithm aes-128-cmac\n",
            "key chain OSPF-KC\n  key 2\n    key-string 7 0822455D0A16\n",
        ):
            with self.subTest(config=config):
                out, _ = redact(config)
                self.assertRegex(out, r"\n +key \d+\n")


class AnXrKeychainNamesAChain(unittest.TestCase):
    """BUG-342: IOS-XR writes `keychain` as one word, and the chain it names is no secret."""

    def test_the_chain_name_stays(self):
        for line in (
            " lsp-password keychain ISIS-KC",
            "  hello-password keychain ISIS-KC",
            " lsp-password keychain ISIS-KC level 2",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_password_written_in_place_still_goes(self):
        out, changed = redact(" lsp-password hmac-md5 encrypted 0822455D0A16")
        self.assertNotIn("0822455D0A16", out)
        self.assertEqual(changed, 1)


class AChainNameEndingInAKeywordIsAName(unittest.TestCase):
    """G22: `ISIS-KEY` read as the keyword `key` cut the level after it, and the reader lost the statement."""

    def test_what_follows_the_name_stays(self):
        for line in (
            " lsp-password keychain ISIS-KEY level 2",
            "  hello-password keychain ISIS-KEY level 1",
            "key chain OSPF-MD5",
            " authentication key-chain RR-SECRET level-1",
            " isis authentication key-chain CORE-PASSWORD level-2",
            " standby 1 authentication md5 key-chain HSRP-KEY",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_secret_after_the_name_still_goes(self):
        for line, kept in (
            ("username bob password keychain foo", "username bob password"),
            ("username bob password keychain ISIS-KEY level 2", "username bob password"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))

    def test_a_line_redacted_before_the_fix_is_left_alone(self):
        line = f" lsp-password keychain ISIS-KEY {REDACTION_MARKER}"
        self.assertEqual(redact(line), (line, 0))


class OnlyAKeywordThatTakesAChainIsFollowedByOne(unittest.TestCase):
    """F-35: `username bob password keychain` kept its password, read as the word that names a chain."""

    def test_a_password_spelled_like_a_chain_is_redacted(self):
        for line, kept in (
            ("username bob password keychain", "username bob password"),
            ("username carol password chain", "username carol password"),
            ("tacacs-server key chain", "tacacs-server key"),
            (" neighbor 10.0.0.2 password key-chain", " neighbor 10.0.0.2 password"),
            (" standby 1 authentication text chain", " standby 1 authentication text"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))

    def test_every_chain_a_platform_names_stays(self):
        for line in (
            "key chain ISIS-KC",
            "key chain MACSEC-KC macsec",
            "mka pre-shared-key key-chain MACSEC-KC",
            " standby 1 authentication md5 key-chain HSRP-KC",
            " vrrp 2 authentication md5 key-chain VRRP-KC",
            "    authentication md5 key-chain HSRP-KC",
            " lsp-password keychain ISIS-KC level 1",
            "  hello-password keychain ISIS-KC",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))


class AnNtpKeyNumberIsNotASecret(unittest.TestCase):
    """BUG-107: the key an NTP association names is a number; what follows it is the association's."""

    def test_the_association_keeps_its_preference_source_and_vrf(self):
        for config in (
            "ntp server 192.0.2.1 key 1 prefer source Loopback0",
            "ntp server vrf MGMT 192.0.2.1 key 1 prefer",
            "ntp peer 192.0.2.2 key 2",
            "ntp server 192.0.2.1 prefer use-vrf management key 1",
            "ntp server 192.0.2.1 key 1 source inside prefer",
            "ntp\n server vrf MGMT 192.0.2.1 key 1 prefer source Loopback0",
            "system {\n    ntp {\n        server 192.0.2.1 key 1 prefer routing-instance mgmt_junos;",
        ):
            with self.subTest(config=config):
                self.assertEqual(redact(config), (config, 0))

    def test_the_keys_themselves_and_a_tacacs_server_private_key_are_still_redacted(self):
        for config, secret in (
            ("ntp authentication-key 1 md5 NtpS3cret 7", "NtpS3cret"),
            ("aaa group server tacacs+ TAC\n server-private 192.0.2.12 key 0 4711", "4711"),
            ("ntp\n server-private 192.0.2.12 key 4711", "4711"),
            ("tacacs-server host 192.0.2.11 key 12345", "12345"),
            ("system {\n    ntp {\n        authentication-key 1 type md5 value NtpS3cret;", "NtpS3cret"),
        ):
            with self.subTest(config=config):
                out, _ = redact(config)
                self.assertNotIn(secret, out)


class AnAsaSnmpHostLineLosesOnlyItsCommunity(unittest.TestCase):
    """BUG-109: ASA names the interface before the address; the address, poll/trap, version and port stay."""

    def test_the_community_goes_and_the_rest_of_the_line_stays(self):
        for line, kept in (
            ("snmp-server host inside 192.0.2.40 community s3cret version 2c",
             f"snmp-server host inside 192.0.2.40 community {REDACTION_MARKER} version 2c"),
            ("snmp-server host mgmt 192.0.2.40 poll community 0 s3cret version 2c udp-port 1162",
             f"snmp-server host mgmt 192.0.2.40 poll community 0 {REDACTION_MARKER} version 2c udp-port 1162"),
            ("snmp-server host mgmt 2001:db8::40 trap community s3cret",
             f"snmp-server host mgmt 2001:db8::40 trap community {REDACTION_MARKER}"),
            ("snmp-server host inside 192.0.2.40 version 3 s3cret",
             f"snmp-server host inside 192.0.2.40 version 3 {REDACTION_MARKER}"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (kept, 1))

    def test_a_host_line_with_no_community_keeps_its_address(self):
        for line in (
            "snmp-server host inside 192.0.2.40 poll",
            "snmp-server host inside 192.0.2.40 trap udp-port 1162",
            "snmp-server host inside 192.0.2.40 version 2c udp-port 1162",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_host_line_that_says_no_asa_word_is_read_as_ios(self):
        """F-13: `inside 192.0.2.40` and IOS's `nms.example.com 10.20.30.40` are one shape; the second word may be the community."""
        for line in (
            "snmp-server host inside 192.0.2.40",
            "snmp-server host nms1 10.20.30.40",
            "snmp-server host nms.example.com 10.20.30.40",
        ):
            with self.subTest(line=line):
                head = line.rsplit(" ", 1)[0]
                self.assertEqual(redact(line), (f"{head} {REDACTION_MARKER}", 1))

    ASA_INTERFACES = (
        "interface GigabitEthernet0/1\n nameif inside\n security-level 100\n!\n"
        "interface Management0/0\n nameif mgmt\n security-level 100\n!\n"
    )

    def test_a_bare_host_line_after_an_interface_the_asa_names_keeps_its_address(self):
        """The receiver takes the global community: the line carries no secret, and the NMS address is a fact."""
        for line in (
            "snmp-server host inside 192.0.2.40",
            "snmp-server host mgmt 2001:db8::40",
            "snmp-server host inside 192.0.2.40 udp-port 1162",
        ):
            with self.subTest(line=line):
                config = self.ASA_INTERFACES + line
                self.assertEqual(redact(config), (config, 0))

    def test_what_is_no_bare_asa_host_line_still_loses_its_second_word(self):
        """Only a name the same output gives an interface, then a valid address, then nothing but a port."""
        for line, secret in (
            # IOS: a host name, then a community shaped like an address.
            ("snmp-server host nms1 10.20.30.40", "10.20.30.40"),
            ("snmp-server host nms.example.com 10.20.30.40", "10.20.30.40"),
            # An interface's name, then a community that is no address.
            ("snmp-server host inside ab:cd:ef", "ab:cd:ef"),
            ("snmp-server host inside 999.1.1.1", "999.1.1.1"),
            ("snmp-server host inside 192.0.2.40 S3CRET", "S3CRET"),
            ("snmp-server host inside 192.0.2.40 community S3CRET", "S3CRET"),
            ("snmp-server host mgmt 192.0.2.40 version 3 S3CRET", "S3CRET"),
        ):
            with self.subTest(line=line):
                out, changed = redact(self.ASA_INTERFACES + line)
                self.assertNotIn(secret, out)
                self.assertEqual(changed, 1)

    def test_an_ios_community_shaped_like_an_address_is_not_read_as_the_asa_form(self):
        """BUG-109: on IOS the address comes first, so a second word shaped like one is the community."""
        for line, secret in (
            ("snmp-server host 192.0.2.9 c0ff:ee", "c0ff:ee"),
            ("snmp-server host 192.0.2.9 10.20.30.40", "10.20.30.40"),
            ("snmp-server host 2001:db8::9 beef:1 udp-port 162", "beef:1"),
            # F-13: after a host name, a community with a colon is no IPv6
            # literal, and one shaped like an address is still the community.
            ("snmp-server host nms.example.com c0ff:ee", "c0ff:ee"),
            ("snmp-server host nms.example.com 1234:5678", "1234:5678"),
            ("snmp-server host nms.example.com 1:2", "1:2"),
            ("snmp-server host nms.example.com 10.20.30.40", "10.20.30.40"),
            ("snmp-server host nms.example.com a:b:c", "a:b:c"),
        ):
            with self.subTest(line=line):
                out, changed = redact(line)
                self.assertNotIn(secret, out)
                self.assertEqual(changed, 1)


class ADescriptionIsFreeText(unittest.TestCase):
    """BUG-330: 'Key Account' in a description is two words, not a keyword and its secret."""

    IOSXE_TABLE = (
        "Interface                      Status         Protocol Description\n"
        "Gi1                            up             up       Key Account uplink to sw-1\n"
        "Gi2                            admin down     down     Key Lab\n"
        "Lo0                            up             up       MD5 test loopback"
    )
    NXOS_TABLE = (
        "-------------------------------------------------------------------------------\n"
        "Port          Type   Speed   Description\n"
        "-------------------------------------------------------------------------------\n"
        "Eth1/1        eth    10G     Key Account uplink\n"
        "\n"
        "-------------------------------------------------------------------------------\n"
        "Interface                Description\n"
        "-------------------------------------------------------------------------------\n"
        "mgmt0                    --\n"
        "Lo0                      Key loopback"
    )
    JUNOS_TABLE = (
        "Interface       Admin Link Description\n"
        "ge-0/0/0        up    up   Key Account uplink\n"
        "ge-0/0/0.100    up    up   Key Lab VLAN"
    )

    def test_a_configured_or_reported_description_keeps_every_word(self):
        for line in (
            " description Key Account uplink to sw-1",
            '        description "MD5 Lab core link";',
            " neighbor 192.0.2.1 description Key Account PE",
            "  Description: Key Account uplink",
            "Port Description: Key Account uplink",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_description_table_keeps_every_row(self):
        for table in (self.IOSXE_TABLE, self.NXOS_TABLE, self.JUNOS_TABLE):
            with self.subTest(table=table.splitlines()[0]):
                self.assertEqual(redact(table), (table, 0))

    def test_what_follows_the_table_in_a_transcript_is_still_redacted(self):
        out, changed = redact(
            self.IOSXE_TABLE + "\nR1#show running-config\nenable secret 5 $1$abcd$KJhg\n"
            "snmp-server community S3cret RO\n"
        )
        self.assertIn("Key Account uplink to sw-1", out)
        self.assertNotIn("$1$abcd$KJhg", out)
        self.assertNotIn("S3cret", out)
        self.assertEqual(changed, 2)

    def test_what_follows_a_credential_word_in_a_description_goes(self):
        """F-36 (owner decision D3): a password typed into a description is still a password."""
        for line, kept in (
            (" description guest wifi password Welcome123", " description guest wifi password"),
            (' description "jump host passwd: Welcome123";', ' description "jump host passwd'),
            (" neighbor 192.0.2.1 description community 65000:1 tagged", " neighbor 192.0.2.1 description community"),
            # The accepted cost: harmless words after one of them go too.
            (" description secret shared with NOC", " description secret"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))

    def test_a_description_table_row_loses_what_follows_a_credential_word(self):
        out, changed = redact(self.IOSXE_TABLE.replace("Key Lab", "Secret Lab"))
        self.assertIn(f"down     Secret {REDACTION_MARKER}\n", out)
        self.assertIn("Key Account uplink to sw-1", out)
        self.assertEqual(changed, 1)

    def test_a_credential_word_with_nothing_after_it_or_inside_another_word_is_kept(self):
        for line in (
            " description to firewall secret",
            '        description "Lab. Secret.";',
            " description passwords rotated by NOC",
            " description S3CRET-customer uplink",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_credentials_in_a_url_in_a_description_still_go(self):
        out, changed = redact(" description backup to scp://backup:B4ckupP4ss@192.0.2.5/cfg")
        self.assertNotIn("B4ckupP4ss", out)
        self.assertIn(" description backup to scp://", out)
        self.assertEqual(changed, 1)


# G19: what redact keeps around a secret. Every case is raw input with an
# obviously fake secret, in documentation address space.
FAKE = "Fak3S3cr3t"
M = REDACTION_MARKER

# (raw input, its last line redacted, the change count, which is the one the
# code gave before G19 for the same input unless the line is now kept whole).
KEPT_AROUND_THE_SECRET = (
    # Bug 4: IOS-XR IS-IS keeps its mode through a second pass (see the
    # idempotence tests); the first pass is as it was.
    (f"router isis CORE\n lsp-password hmac-md5 encrypted {FAKE}", f" lsp-password hmac-md5 encrypted {M}", 1),
    (f"router isis CORE\n lsp-password hmac-md5 encrypted {FAKE} level 2 send-only",
     f" lsp-password hmac-md5 encrypted {M} level 2 send-only", 1),
    # Bug 5: a keyring's peer address, and its mask, stay.
    (f"crypto keyring KR\n pre-shared-key address 192.0.2.1 key {FAKE}",
     f" pre-shared-key address 192.0.2.1 key {M}", 1),
    (f"crypto keyring KR\n  pre-shared-key address 192.0.2.0 255.255.255.0 key {FAKE}",
     f"  pre-shared-key address 192.0.2.0 255.255.255.0 key {M}", 1),
    (f"crypto keyring KR\n pre-shared-key address ipv6 2001:db8::1/128 key {FAKE}",
     f" pre-shared-key address ipv6 2001:db8::1/128 key {M}", 1),
    # With an encryption type the whole value after `key` goes, as before.
    (f"crypto keyring KR\n pre-shared-key address 192.0.2.1 key 6 {FAKE}",
     f" pre-shared-key address 192.0.2.1 key {M}", 1),
    # Bug 6: a transform-set's transforms stay, whatever its name. Before, the
    # line was cut (count 1); kept whole it is no change (count 0).
    ("crypto ipsec transform-set TS-AES256-SHA512 esp-aes 256 esp-sha512-hmac",
     "crypto ipsec transform-set TS-AES256-SHA512 esp-aes 256 esp-sha512-hmac", 0),
    ("crypto ipsec transform-set esp-aes-sha esp-aes esp-sha-hmac",
     "crypto ipsec transform-set esp-aes-sha esp-aes esp-sha-hmac", 0),
    ("crypto ipsec transform-set esp-aes256-sha esp-aes 256 esp-sha-hmac ",
     "crypto ipsec transform-set esp-aes256-sha esp-aes 256 esp-sha-hmac ", 0),
    ("crypto ipsec ikev1 transform-set TS-AES-SHA esp-aes-256 esp-sha-hmac",
     "crypto ipsec ikev1 transform-set TS-AES-SHA esp-aes-256 esp-sha-hmac", 0),
    # BUG-COLLECTOR-JUNOS-REDACT-SEMICOLON: a Junos leaf keeps its `;`.
    (f"protocols {{\n    isis {{\n        authentication-key {FAKE};",
     f"        authentication-key {M};", 1),
    (f'protocols {{\n    isis {{\n        authentication-key "{FAKE}";',
     f"        authentication-key {M};", 1),
    (f'protocols {{\n    isis {{\n        authentication-key "$9${FAKE}"; ## SECRET-DATA',
     f"        authentication-key {M};", 1),
    (f'system {{\n    root-authentication {{\n        encrypted-password "$6${FAKE}"; ## SECRET-DATA',
     f"        encrypted-password {M};", 1),
    (f'system {{\n    tacplus-server {{\n        192.0.2.5 {{\n            secret "{FAKE}";',
     f"            secret {M};", 1),
    # A `;` inside the quotes is the secret's, the one after them the leaf's.
    (f'system {{\n    tacplus-server {{\n        192.0.2.5 {{\n            secret "{FAKE};x";',
     f"            secret {M};", 1),
    # The braces that close on the same line stay with the `;`.
    (f"security {{\n    ike {{\n        policy P {{ pre-shared-key ascii-text {FAKE}; }}",
     f"        policy P {{ pre-shared-key {M}; }}", 1),
    # BUG-COLLECTOR-ISAKMP-KEY-ENCTYPE: the type digit and the peer stay.
    (f"crypto isakmp key 0 {FAKE} address 192.0.2.1", f"crypto isakmp key 0 {M} address 192.0.2.1", 1),
    (f"crypto isakmp key 6 {FAKE} address 192.0.2.1", f"crypto isakmp key 6 {M} address 192.0.2.1", 1),
    (f"crypto isakmp key 7 {FAKE} address 192.0.2.1 no-xauth", f"crypto isakmp key 7 {M} address 192.0.2.1 no-xauth", 1),
    (f"crypto isakmp key 6 {FAKE} address 192.0.2.0 255.255.255.0",
     f"crypto isakmp key 6 {M} address 192.0.2.0 255.255.255.0", 1),
    # G32, BUG-COLLECTOR-EAP-MD5-CUT: `eap md5` is a method word; the username
    # stays and `password` cuts the password. Before: `... eap md5 {M}`.
    (f"crypto ikev2 profile P\n authentication local eap md5 username U1 password {FAKE}",
     f" authentication local eap md5 username U1 password {M}", 1),
    (f"crypto ikev2 profile P\n authentication local eap md5 username U1 password 0 {FAKE}",
     f" authentication local eap md5 username U1 password {M}", 1),
    (f"crypto ikev2 profile P\n authentication remote eap md5 password 6 {FAKE}",
     f" authentication remote eap md5 password {M}", 1),
    # With no password nothing is cut (before: `eap md5 {M}`, count 1).
    ("crypto ikev2 profile P\n authentication local eap md5 username U1",
     " authentication local eap md5 username U1", 0),
)

# Variants that must still be cut as they were before G19.
STILL_CUT = (
    (f"crypto keyring KR\n pre-shared-key key {FAKE}", f" pre-shared-key {M}"),
    (f"crypto keyring KR\n pre-shared-key hostname peer.example.net key {FAKE}", f" pre-shared-key {M}"),
    # An address that is no address is no peer.
    (f"crypto keyring KR\n pre-shared-key address {FAKE} key x", f" pre-shared-key {M}"),
    (f"crypto isakmp key {FAKE} hostname peer.example.net", f"crypto isakmp key {M}"),
    (f"crypto isakmp key 6 {FAKE} hostname peer.example.net", f"crypto isakmp key {M}"),
    # A key that is one digit is the key, and goes.
    ("crypto isakmp key 6 address 192.0.2.1", f"crypto isakmp key {M} address 192.0.2.1"),
    # The grammar gives a transform-set no secret (`crypto ipsec transform-set
    # NAME TRANSFORM...`). A name that is a keyword whole is still read as
    # one, and a secret written after a masked name is still cut.
    ("crypto ipsec transform-set SHA esp-aes esp-sha-hmac", f"crypto ipsec transform-set SHA {M}"),
    (f"crypto ipsec transform-set TS-MD5 esp-aes password {FAKE}", f"crypto ipsec transform-set TS-MD5 esp-aes password {M}"),
    # Outside a Junos block a `;` may be part of the secret: it goes.
    (f"username ops password 0 {FAKE};", f"username ops password {M}"),
    (f"authentication-key {FAKE};", f"authentication-key {M}"),
    # A Junos value with another annotation after it, or a list, is cut whole.
    (f"protocols {{\n    isis {{\n        authentication-key {FAKE}; /* {FAKE} */", f"        authentication-key {M}"),
    (f"protocols {{\n    isis {{\n        authentication-key {FAKE}; ## rotated {FAKE}", f"        authentication-key {M}"),
    (f"system {{\n    services {{\n        key-exchange [ dh-group14-sha1 {FAKE} ];", f"        key-exchange [ dh-group14-sha1 {M}"),
    # G32: `eap md5` outside the documented `[username <u>] [password ...]`
    # tail is cut at `md5` as before; a username that is a keyword is cut
    # where it stands (more kept than before, the password still gone).
    (f"crypto ikev2 profile P\n authentication local eap md5 {FAKE}", f" authentication local eap md5 {M}"),
    (f"crypto ikev2 profile P\n authentication local eap md5 username U1 {FAKE}", f" authentication local eap md5 {M}"),
    (f"crypto ikev2 profile P\n authentication local eap md5 username md5 password {FAKE}",
     f" authentication local eap md5 username md5 {M}"),
    (f"crypto ikev2 profile P\n authentication local eap gtc md5 {FAKE}", f" authentication local eap gtc md5 {M}"),
)


class RedactionKeepsTheContextAroundTheSecret(unittest.TestCase):
    """G19: bugs 4, 5 and 6, the Junos `;` and the ISAKMP key's type digit.

    Each fix cuts exactly the secret it cut before and keeps more of the
    text around it.
    """

    def test_the_context_stays_and_the_secret_goes(self):
        for raw, kept, count in KEPT_AROUND_THE_SECRET:
            with self.subTest(raw=raw):
                out, changed = redact(raw)
                self.assertEqual(out.splitlines()[-1], kept)
                self.assertNotIn(FAKE, out)
                self.assertEqual(changed, count)

    def test_the_variants_outside_the_fixed_shapes_are_cut_as_before(self):
        for raw, cut in STILL_CUT:
            with self.subTest(raw=raw):
                out, changed = redact(raw)
                self.assertEqual(out.splitlines()[-1], cut)
                self.assertNotIn(FAKE, out)
                self.assertEqual(changed, 1)


class RedactionIsIdempotent(unittest.TestCase):
    """Bug 4: redact over redacted text changes nothing and counts nothing.

    Exports and re-runs on a snapshot redact stored text again; a second
    pass that cut further lost the context the first one kept.
    """


    def test_the_isis_mode_survives_a_second_pass(self):
        once, _ = redact(f"router isis CORE\n lsp-password hmac-md5 encrypted {FAKE} level 2")
        self.assertEqual(redact(once), (once, 0))
        self.assertIn(f"lsp-password hmac-md5 encrypted {M} level 2", once)


class EapMd5IsAMethodWord(unittest.TestCase):
    """G32, BUG-COLLECTOR-EAP-MD5-CUT: `eap md5` names the method, as `md5 key-chain` names a chain.

    Cisco IOS XE Security Command Reference, `authentication (IKEv2
    profile)`: `authentication {local | remote} eap [gtc | md5 | mschapv2]
    [username <u>] [password [0|6] <p>]`. Every case cuts at least what the
    code cut before of the secret and keeps more of the rest, or cuts as
    before; no demo line has `eap md5`.
    """

    # (raw line, redacted before G32, redacted now)
    CASES = (
        (f" authentication local eap md5 username U1 password {FAKE}",
         f" authentication local eap md5 {M}", f" authentication local eap md5 username U1 password {M}"),
        (f" authentication local eap md5 username U1 password 0 {FAKE}",
         f" authentication local eap md5 {M}", f" authentication local eap md5 username U1 password {M}"),
        (f" authentication local eap md5 password {FAKE}",
         f" authentication local eap md5 {M}", f" authentication local eap md5 password {M}"),
        (f" authentication local eap md5 username md5 password {FAKE}",
         f" authentication local eap md5 {M}", f" authentication local eap md5 username md5 {M}"),
        (f" authentication  remote  eap   md5  username U1  password  6 {FAKE}",
         f" authentication  remote  eap   md5 {M}", f" authentication  remote  eap   md5  username U1  password {M}"),
        (f" AUTHENTICATION LOCAL EAP MD5 USERNAME U1 PASSWORD {FAKE}",
         f" AUTHENTICATION LOCAL EAP MD5 {M}", f" AUTHENTICATION LOCAL EAP MD5 USERNAME U1 PASSWORD {M}"),
        (" authentication local eap md5 username U1",
         f" authentication local eap md5 {M}", " authentication local eap md5 username U1"),
        # `password` takes the rest of the line, as it always has.
        (f" authentication local eap md5 username U1 password 0 {FAKE} trailing",
         f" authentication local eap md5 {M}", f" authentication local eap md5 username U1 password {M}"),
    )
    # Lines the rule leaves as they were: `md5` anywhere but the method word
    # of that statement, or an `eap md5` with an undocumented tail.
    UNCHANGED = (
        f" authentication local eap md5 {FAKE}",
        f" authentication local eap md5 username U1 {FAKE}",
        f" authentication local eap gtc md5 {FAKE}",
        f" dot1x eap md5 {FAKE}",
        f" hash md5 {FAKE}",
        " integrity md5 sha1",
        "crypto ipsec transform-set TS esp-aes esp-md5-hmac",
        f" ip ospf message-digest-key 1 md5 {FAKE}",
        f" ip ospf authentication-key 7 {FAKE}",
        "  message-digest-key 1 md5 encrypted 0123ABCD",
        " isis authentication mode md5 level-2",
        f" isis password {FAKE} level-2",
        f" neighbor 192.0.2.1 password 7 {FAKE}",
        f" neighbor 192.0.2.1 password {FAKE}",
        " standby 1 authentication md5 key-chain HSRP-KC",
        f" standby 1 authentication md5 key-string {FAKE}",
        f" lsp-password hmac-md5 encrypted {FAKE} level 2",
        f"ntp authentication-key 1 md5 {FAKE} 7",
    )

    def test_the_username_stays_and_the_password_goes(self):
        for raw, before, now in self.CASES:
            with self.subTest(raw=raw):
                out, changed = redact(raw)
                self.assertEqual(out, now)
                self.assertNotIn(FAKE, out)
                self.assertEqual(changed, int(now != raw))
                # At least as much of the secret cut as before, and more kept.
                self.assertTrue(now.startswith(before[: -len(M)].rstrip()))

    def test_other_md5_lines_redact_as_the_keyword_rule_always_did(self):
        from netstate.collector import SECRET_LINE, _secret_line

        for raw in self.UNCHANGED:
            with self.subTest(raw=raw):
                out, _ = redact(raw)
                self.assertNotIn(FAKE, out)
                match = _secret_line(raw)
                # The method rule fires only where `eap md5` is the method of
                # the documented shape: everywhere else the match is the one
                # the keyword pattern alone gives.
                plain = SECRET_LINE.match(raw)
                self.assertEqual(match.end("keep") if match else None, plain.end("keep") if plain else None)

    def test_a_second_pass_changes_nothing(self):
        for raw, _before, now in self.CASES:
            with self.subTest(raw=raw):
                self.assertEqual(redact(now), (now, 0))
        for line in (f" authentication local eap md5 {M}", f" authentication local eap md5 username md5 {M}"):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_in_a_configuration_the_neighbours_are_untouched(self):
        config = (
            "crypto ikev2 profile P\n"
            f" authentication local eap md5 username U1 password 6 {FAKE}\n"
            " authentication remote eap md5\n"
            "router ospf 1\n"
            " area 0 authentication message-digest\n"
            "interface Gi1\n"
            f" ip ospf message-digest-key 1 md5 {FAKE}\n"
            "router bgp 64512\n"
            f" neighbor 192.0.2.1 password {FAKE}\n"
        )
        out, changed = redact(config)
        self.assertNotIn(FAKE, out)
        self.assertEqual(changed, 3)
        self.assertEqual(out.splitlines(), [
            "crypto ikev2 profile P",
            f" authentication local eap md5 username U1 password {M}",
            " authentication remote eap md5",
            "router ospf 1",
            " area 0 authentication message-digest",
            "interface Gi1",
            f" ip ospf message-digest-key {M}",
            "router bgp 64512",
            f" neighbor 192.0.2.1 password {M}",
        ])


# G25: a `## SECRET-DATA` line keeps the words before its quoted `$n$` value.
# Each case is (the line as Junos prints it, inside a block, with a fake
# secret; what redact made of it before G25; what it makes of it now).
_IN_BLOCK = "system {\n    archival {\n"
SECRET_DATA_KEPT = (
    # system archival archive-sites, as Junos prints them.
    (f'        "ftp://contact05@example.net/pe1" password "$9${FAKE}"; ## SECRET-DATA',
     f'        "ftp://contact05@example.net/pe1" {M};',
     f'        "ftp://contact05@example.net/pe1" password {M};'),
    # A URL whose credentials the URL pass already replaced keeps them replaced.
    (f'        "scp://ops:{FAKE}@192.0.2.1/cfg" password "$9${FAKE}"; ## SECRET-DATA',
     f'        "scp://{M}@192.0.2.1/cfg" {M};',
     f'        "scp://{M}@192.0.2.1/cfg" password {M};'),
    # RADIUS and TACACS+ servers given inline.
    (f'        192.0.2.5 secret "$9${FAKE}"; ## SECRET-DATA', f"        192.0.2.5 {M};", f"        192.0.2.5 secret {M};"),
    (f'        192.0.2.5 port 1812 secret "$9${FAKE}"; ## SECRET-DATA', f"        192.0.2.5 {M};",
     f"        192.0.2.5 port 1812 secret {M};"),
    # OSPF MD5, IKE, NTP: the key id, `key` and the format word stay.
    (f'        authentication md5 1 key "$9${FAKE}"; ## SECRET-DATA', f"        authentication {M};",
     f"        authentication md5 1 key {M};"),
    (f'        md5 1 key "$9${FAKE}"; ## SECRET-DATA', f"        md5 {M};", f"        md5 1 key {M};"),
    (f'        pre-shared-key ascii-text "$9${FAKE}"; ## SECRET-DATA', f"        pre-shared-key {M};",
     f"        pre-shared-key ascii-text {M};"),
    (f'        pre-shared-key hexadecimal "$9${FAKE}"; ## SECRET-DATA', f"        pre-shared-key {M};",
     f"        pre-shared-key hexadecimal {M};"),
    (f'        authentication-key 1 type md5 value "$9${FAKE}"; ## SECRET-DATA', f"        authentication-key {M};",
     f"        authentication-key 1 type md5 value {M};"),
    (f'        level 2 hello-authentication-key "$9${FAKE}"; ## SECRET-DATA', f"        level {M};",
     f"        level 2 hello-authentication-key {M};"),
    # Single-keyword lines come out as before.
    (f'        encrypted-password "$6$ab${FAKE}"; ## SECRET-DATA', f"        encrypted-password {M};",
     f"        encrypted-password {M};"),
    # Closing braces on the same line stay with the `;`.
    (f'        secret "$9${FAKE}"; }} }} ## SECRET-DATA', f"        secret {M}; }} }}", f"        secret {M}; }} }}"),
    # A value that is the first word was kept by the first-word rule: it leaked.
    (f'        "$9${FAKE}"; ## SECRET-DATA', f'        "$9${FAKE}"; {M}', f"        {M};"),
)
# Shapes the rule does not keep more of: cut as before, or more.
SECRET_DATA_STILL_CUT = (
    # No quoted `$n$` value: an unquoted value, a plain-text quoted one.
    (f"        secret {FAKE}; ## SECRET-DATA", f"        secret {M};"),
    (f'        secret "{FAKE}"; ## SECRET-DATA', f"        secret {M};"),
    (f'        "scp://ops:{FAKE}@192.0.2.1/cfg" password {FAKE}; ## SECRET-DATA', f'        "scp://{M}@192.0.2.1/cfg" {M};'),
    (f'        ssh-rsa "ssh-rsa AAAA{FAKE} ops@host"; ## SECRET-DATA', f"        ssh-rsa {M};"),
    # Two secrets on one line: cut from the first.
    (f'        secret "$9${FAKE}" "$9${FAKE}2"; ## SECRET-DATA', f"        secret {M};"),
    # A secret followed by more words: they go.
    (f'        secret "$9${FAKE}" {FAKE} more; ## SECRET-DATA', f"        secret {M};"),
    # A `;` inside the quotes is the secret's.
    (f'        secret "$9${FAKE};{FAKE}"; ## SECRET-DATA', f"        secret {M};"),
    # Shapes not read word by word: an unclosed quote, a brace, a comment, an annotation before.
    (f'        secret "$9${FAKE} ## SECRET-DATA', f"        secret {M}"),
    (f'        policy P {{ pre-shared-key ascii-text "$9${FAKE}"; }} ## SECRET-DATA', f"        policy {M}"),
    (f'        secret /* {FAKE} */ "$9${FAKE}"; ## SECRET-DATA', f"        secret {M};"),
    (f'        secret ## "$9${FAKE}" ## SECRET-DATA', f"        secret {M}"),
)


class AJunosSecretDataLineKeepsTheWordsBeforeItsValue(unittest.TestCase):
    """G25, BUG-COLLECTOR-JUNOS-SECRET-DATA-FIRST-WORD: the statement around a marked secret stays.

    Junos marks the line, and prints the secret quoted in a `$n$` form; the
    words before that value are the statement. Every case cuts at least what
    the first-word rule cut of the secret.
    """

    def test_the_statement_stays_and_the_value_goes(self):
        for raw, before, now in SECRET_DATA_KEPT:
            with self.subTest(raw=raw):
                out, changed = redact(_IN_BLOCK + raw)
                self.assertEqual(out.splitlines()[-1], now)
                self.assertNotIn(FAKE, out)
                self.assertNotIn("$9$", out)
                self.assertNotIn("SECRET-DATA", out)
                self.assertEqual(changed, 1)

    def test_outside_a_block_the_semicolon_goes_as_on_every_other_line(self):
        for raw, _, now in SECRET_DATA_KEPT:
            with self.subTest(raw=raw):
                out, changed = redact(raw.strip())
                expected = re.sub(r"\s*;(?:\s*\})*$", "", now.strip())
                self.assertEqual(out, expected)
                self.assertNotIn(FAKE, out)

    def test_the_other_shapes_are_cut_at_least_as_before(self):
        for raw, cut in SECRET_DATA_STILL_CUT:
            with self.subTest(raw=raw):
                out, changed = redact(_IN_BLOCK + raw)
                self.assertEqual(out.splitlines()[-1], cut)
                self.assertNotIn(FAKE, out)
                self.assertNotIn("$9$", out)
                self.assertEqual(changed, 1)

    def test_a_second_pass_changes_nothing(self):
        for raw in [case[0] for case in SECRET_DATA_KEPT] + [case[0] for case in SECRET_DATA_STILL_CUT]:
            for text in (_IN_BLOCK + raw, raw.strip()):
                first, _ = redact(text)
                with self.subTest(text=text):
                    self.assertEqual(redact(first), (first, 0))

    def test_the_grammar_words_kept_for_a_second_pass_still_lose_a_value_that_is_no_marker(self):
        """The second-pass exemption reads only the marker as the value; any other value goes as before."""
        for raw, cut in (
            (f"        md5 1 key {FAKE};", f"        md5 {M};"),
            (f"        authentication md5 1 key {FAKE};", f"        authentication md5 {M};"),
            (f"        pre-shared-key ascii-text {FAKE};", f"        pre-shared-key {M};"),
            (f"        authentication-key 1 type md5 value {FAKE};", f"        authentication-key {M};"),
            (f"        md5 1 key {FAKE} {M};", f"        md5 {M};"),
        ):
            with self.subTest(raw=raw):
                out, _ = redact(_IN_BLOCK + raw)
                self.assertEqual(out.splitlines()[-1], cut)


if __name__ == "__main__":
    unittest.main()
