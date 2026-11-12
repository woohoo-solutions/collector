"""Every line of a realistic configuration, redacted to a result decided by hand.

The keyword rules were tuned one complaint at a time, and each tuning moved
lines nobody was looking at: a fix for `Key Account` in a description let a
password typed into one through, and a fix for the ASA host line let an IOS
community with a colon in it through. A battery that compared the new code
with the old could only say that a line had changed, not whether it was now
right, and it read a description naming an `S3CRET-customer` as a leak and a
community written in clear as kept. So each fragment below, one per platform
and one of operational output, has its expected redaction written out line by
line, and the test holds the code to it.

How each line was decided: a secret goes, with everything after the keyword
that introduces it, as `SECRET_LINE` has always done. What names a secret
without being one stays: a key's number, a key chain's name, an
authentication mode. A description is free text and keeps its words, except
what follows `password`, `passwd`, `secret` or `community` in it (owner
decision D3); `key` is never such a word there, because `Key Account` names
a customer. Banners and the Junos login message
are read by the same rule.

The lines the code does not get right yet are listed in `KNOWN`, under the
finding that fixes them, or under `open` where no finding covers them yet.
Each group has a test of its own that is expected to fail, and the fix that
makes it pass removes the group, so its lines join the ones every run holds.
Test data only: private and documentation addresses, and no real names.
"""

from __future__ import annotations

import unittest

from netstate.collector import REDACTION_MARKER, redact

FRAGMENTS = {
    "IOS-XE": """\
version 17.9
service password-encryption
hostname PE1
boot-start-marker
enable secret 9 $9$abcdef
enable password 7 0123456789
username admin privilege 15 secret 9 $9$S3CRET
username oper password 7 Pa55w0rd
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
tacacs server TAC1
 address ipv4 10.0.0.5
 key 7 Pa55w0rd
 timeout 5
radius server RAD1
 address ipv4 10.0.0.6 auth-port 1812 acct-port 1813
 key 123456
aaa group server tacacs+ TACGRP
 server name TAC1
 server-private 10.0.0.7 key 7 Pa55w0rd
key chain ISIS-KC
 key 1
  key-string 7 Pa55w0rd
  cryptographic-algorithm hmac-sha-256
  accept-lifetime 00:00:00 Jan 1 2020 infinite
 key 2
  key-string k3y
key chain MACSEC-KC macsec
 key 01
  cryptographic-algorithm aes-128-cmac
  key-string Pa55w0rd
crypto isakmp policy 10
 encr aes 256
 authentication pre-share
 group 14
crypto isakmp policy 20
 authentication rsa-encr
 group 14
crypto isakmp policy 30
 authentication ecdsa-sig
 group 19
crypto isakmp key S3CRET address 192.0.2.1
crypto isakmp key S3CRET hostname peer.example.com
crypto keyring KR
 pre-shared-key address 192.0.2.2 key S3CRET
crypto ikev2 keyring IKEV2-KR
 peer HUB
  address 192.0.2.3
  pre-shared-key local S3CRET
  pre-shared-key remote S3CRET
crypto ikev2 profile IKEV2-P
 match identity remote address 192.0.2.3 255.255.255.255
 authentication remote pre-share
 authentication local pre-share
 keyring local IKEV2-KR
crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac
 mode tunnel
crypto ipsec profile IPSEC-P
 set transform-set TS
interface Loopback0
 description Key Account loopback for S3CRET-customer
 ip address 10.255.0.1 255.255.255.255
interface GigabitEthernet1
 description Uplink to CORE password: none secret shared with NOC
 ip address 10.1.1.1 255.255.255.252
 ip ospf message-digest-key 1 md5 7 Pa55w0rd
 ip ospf authentication message-digest
 ip ospf authentication key-chain OSPF-KC
 ip rip authentication key-chain RIP-KC
 ip rip authentication mode md5
 isis authentication mode md5 level-2
 isis authentication key-chain ISIS-KC level-2
 standby 1 ip 10.1.1.3
 standby 1 authentication text Pa55w0rd
 standby 1 authentication md5 key-string 7 Pa55w0rd
 standby 1 authentication md5 key-chain HSRP-KC
 vrrp 2 authentication text Pa55w0rd
 glbp 3 authentication md5 key-string Pa55w0rd
 ip nhrp authentication S3CRET
 ip nhrp map multicast dynamic
 tunnel protection ipsec profile IPSEC-P
interface Vlan10
 description Mgmt - key account
 ip address 10.10.10.1 255.255.255.0
interface Vlan20
 description guest wifi password Welcome123
 ip address 10.10.20.1 255.255.255.0
router ospf 1
 router-id 10.255.0.1
 area 0 authentication message-digest
router isis CORE
 net 49.0001.0100.2550.0001.00
 authentication mode md5 level-2
 authentication key-chain ISIS-KC level-2
 lsp-password keychain X
router bgp 65000
 neighbor 10.255.0.2 remote-as 65000
 neighbor 10.255.0.2 password 7 Pa55w0rd
 neighbor 10.255.0.2 description iBGP to PE2 key account
 neighbor 10.255.0.2 update-source Loopback0
 address-family ipv4
  neighbor 10.255.0.2 activate
  neighbor 10.255.0.2 send-community both
 address-family vpnv4
  neighbor 10.255.0.2 send-community extended
ip route 0.0.0.0 0.0.0.0 10.1.1.2
snmp-server community c0mmun1ty RO ACL-SNMP
snmp-server community c0mmun1ty2 RW
snmp-server community-map c0mmun1ty context ctx
snmp-server location Belgrade DC1 rack 12
snmp-server contact noc@example.com
snmp-server host 192.0.2.9 version 2c c0mmun1ty
snmp-server host 192.0.2.9 informs version 3 auth snmpuser
snmp-server host nms.example.com c0mmun1ty
snmp-server host nms.example.com c0ff:ee
snmp-server host nms.example.com 1234:5678
snmp-server host nms.example.com 1:2
snmp-server host nms.example.com 10.20.30.40
snmp-server host nms.example.com traps version 2c c0mmun1ty
snmp-server host 2001:db8::9 version 2c c0mmun1ty
snmp-server host 192.0.2.9 vrf MGMT version 2c c0mmun1ty udp-port 1162
snmp-server user snmpuser GRP v3 auth sha Pa55w0rd priv aes 128 Pa55w0rd
snmp-server group GRP v3 priv
snmp-server view ALL iso included
snmp-server trap-source Loopback0
snmp-server enable traps bgp
ntp authentication-key 1 md5 Pa55w0rd 7
ntp authenticate
ntp trusted-key 1
ntp server 192.0.2.1 key 1 prefer source Loopback0
ntp server vrf MGMT 192.0.2.2 key 2
ntp peer 192.0.2.3 key 1
ntp server 192.0.2.4
archive
 path scp://admin:p@ss/w0rd@10.0.0.1/backups/$h-$t
 path tftp://10.0.0.1:69/cfg@site
 path ftp://admin:Pa55w0rd@10.0.0.1/cfg
 path scp://admin:1234/x@10.0.0.1/cfg
 path scp://admin.ops:1234/x@10.0.0.1/cfg
 path ftp://:Pa55w0rd@10.0.0.1/cfg
 path scp://admin:"Pa55w0rd k3y"@10.0.0.1/cfg
 path flash:/archive
ip http client username admin
ip http client password 7 Pa55w0rd
ip ssh server algorithm mac hmac-sha2-256
ip ssh server algorithm encryption aes256-ctr
crypto pki trustpoint CA
 enrollment url http://ca.example.com:80/certsrv
 enrollment url http://ca.example.com:80/certsrv/mscep/mscep.dll@site
 password 7 Pa55w0rd
 subject-name CN=PE1
dot11 ssid CORP
 authentication open
 authentication shared
 authentication key-management wpa version 2
 wpa-psk ascii 7 Pa55w0rd
interface GigabitEthernet1/0/1
 description access port key card readers
 switchport mode access
 authentication port-control auto
 authentication open
 authentication periodic
 authentication order dot1x mab
 authentication host-mode multi-auth
 authentication violation restrict
 authentication event fail action next-method
 authentication timer reauthenticate server
 dot1x pae authenticator
 mab
line vty 0 4
 password 7 Pa55w0rd
 login local
 transport input ssh
banner motd ^C
Authorized access only. Key personnel: NOC. Secret handshake required.
^C
mpls ldp neighbor 10.255.0.2 password Pa55w0rd
mpls ldp password required
mpls ldp password option 1 for ACL1 Pa55w0rd
router ospfv3 1
 area 0 authentication ipsec spi 500 sha1 Pa55w0rd
 area 1 encryption ipsec spi 501 esp aes-cbc 128 Pa55w0rd sha1 Pa55w0rd
 area 2 encryption ipsec spi 502 esp null sha1 Pa55w0rd
ipv6 ospf authentication ipsec spi 256 md5 Pa55w0rd
macsec
mka policy MKA
 key-server priority 10
 macsec-cipher-suite gcm-aes-256
mka pre-shared-key key-chain MACSEC-KC
username bob password keychain
username carol password chain
crypto pki token default user-pin 0 Pa55w0rd
crypto pki token default removal timeout 0
parameter-map type umbrella global
 token 0123456789ABCDEFPa55w0rd
 local-domain LOCAL-DOMAINS
license smart trust idtoken Pa55w0rd local
event manager environment _password Pa55w0rd
event manager environment _email_password Pa55w0rd
event manager environment _secret Pa55w0rd
event manager environment _key Pa55w0rd
event manager environment _login_pw Pa55w0rd
event manager applet ROTATE
 event timer cron cron-entry "0 3 * * *"
 action 1.0 cli command "enable" pattern "[Pp]assword"
 action 1.1 cli command "Pa55w0rd"
 action 2.0 cli command "configure terminal"
 action 3.0 cli command "snmp-server community c0mmun1ty RO"
 action 4.0 cli command "snmp-server host 192.0.2.9 version 2c c0mmun1ty"
 action 5.0 cli command "username u secret 0 Pa55w0rd"
 action 6.0 cli command "end"
""",
    "IOS-XR": """\
hostname PE-XR
username admin
 group root-lr
 secret 10 $6$S3CRET
 password 7 Pa55w0rd
!
tacacs-server host 10.0.0.5 port 49
 key 7 Pa55w0rd
!
radius-server host 10.0.0.6 auth-port 1812 acct-port 1813
 key 7 Pa55w0rd
!
key chain ISIS-KC
 key 1
  accept-lifetime 00:00:00 january 01 2020 infinite
  key-string password 0123Pa55w0rd
  send-lifetime 00:00:00 january 01 2020 infinite
  cryptographic-algorithm HMAC-MD5
 !
 key 2
  key-string clear k3y
 !
!
key chain BGP-KC
 key 1
  key-string password 0123
  cryptographic-algorithm HMAC-SHA1-20
!
ntp
 authentication-key 1 md5 encrypted 0123Pa55w0rd
 authenticate
 trusted-key 1
 server 192.0.2.1 key 1 prefer
 server vrf MGMT 192.0.2.2 key 1
 peer 192.0.2.3 key 1
 source Loopback0
 update-calendar
!
interface Loopback0
 description Key Account loopback
 ipv4 address 10.255.0.1 255.255.255.255
!
interface MgmtEth0/RP0/CPU0/0
 description OOB management key
 ipv4 address 10.10.10.2 255.255.255.0
!
interface GigabitEthernet0/0/0/0
 description Uplink to CORE - key account
 ipv4 address 10.1.1.1 255.255.255.252
!
router static
 address-family ipv4 unicast
  0.0.0.0/0 10.1.1.2
 !
!
router isis CORE
 net 49.0001.0100.2550.0001.00
 lsp-password keychain ISIS-KC
 lsp-password hmac-md5 encrypted 0123Pa55w0rd level 2
 lsp-password keychain ISIS-KC level 1
 address-family ipv4 unicast
  metric-style wide
  segment-routing mpls
 !
 interface GigabitEthernet0/0/0/0
  hello-password keychain ISIS-KC level 2
  hello-password hmac-md5 encrypted 0123Pa55w0rd
  hello-password keychain ISIS-KC
  point-to-point
 !
!
router ospf 1
 router-id 10.255.0.1
 area 0
  authentication message-digest
  authentication keychain OSPF-KC
  message-digest-key 1 md5 encrypted 0123Pa55w0rd
  authentication-key encrypted 0123Pa55w0rd
  interface GigabitEthernet0/0/0/0
   authentication
   authentication null
  !
 !
!
router ospfv3 1
 area 1
  authentication disable
 !
 area 0
  authentication ipsec spi 500 sha1 password 0123Pa55w0rd
  encryption ipsec spi 501 esp aes 192 clear Pa55w0rd sha1 clear Pa55w0rd
  encryption ipsec spi 502 esp 3des clear Pa55w0rd
 !
!
router bgp 65000
 bgp router-id 10.255.0.1
 address-family ipv4 unicast
 !
 neighbor 10.255.0.2
  remote-as 65000
  password encrypted 0123Pa55w0rd
  keychain BGP-KC
  description iBGP to PE2 key account
  update-source Loopback0
  address-family ipv4 unicast
  !
 !
!
router hsrp
 interface GigabitEthernet0/0/0/1
  address-family ipv4
   hsrp 1
    authentication Pa55w0rd
    address 192.0.2.123
    priority 110
   !
  !
 !
!
router vrrp
 interface GigabitEthernet0/0/0/1
  address-family ipv4
   vrrp 2
    text-authentication Pa55w0rd
   !
  !
 !
!
snmp-server community c0mmun1ty RO SystemOwner
snmp-server community-map c0mmun1ty context ctx
snmp-server host 192.0.2.9 traps version 2c c0mmun1ty
snmp-server host 192.0.2.9 traps version 3 priv snmpuser udp-port 162
snmp-server vrf MGMT
 host 192.0.2.10 traps version 2c c0mmun1ty
 host 192.0.2.11 informs version 2c c0mmun1ty
 host 192.0.2.12 encrypted 0123Pa55w0rd
 host 192.0.2.13 clear c0mmun1ty udp-port 1162
!
snmp-server user snmpuser GRP v3 auth sha encrypted 0123Pa55w0rd priv aes 128 encrypted 0123Pa55w0rd SystemOwner
snmp-server location Belgrade DC1 rack 12
snmp-server contact noc@example.com
snmp-server trap-source Loopback0
snmp-server traps bgp
mpls ldp
 router-id 10.255.0.1
 neighbor 10.255.0.2:0 password encrypted 0123Pa55w0rd
 neighbor password encrypted 0123Pa55w0rd
 interface GigabitEthernet0/0/0/0
 !
!
ssh server v2
ssh server algorithms key-exchange ecdh-sha2-nistp256
ssh server algorithms cipher aes256-ctr
ssh server algorithms hostkey ecdsa-nistp256
ssh server vrf MGMT
banner motd #
Authorized access only. Key personnel only. Secret.
#
aaa authentication login default group TACGRP local
aaa group server tacacs+ TACGRP
 server 10.0.0.5
 server-private 10.0.0.7 port 49
  key 7 Pa55w0rd
 !
!
lpts pifib hardware police
 flow bgp known rate 2500
!
""",
    "NX-OS": """\
version 10.2(3)
hostname N9K-1
feature bgp
feature ospf
feature interface-vlan
feature lldp
feature nxapi
username admin password 5 $5$S3CRET role network-admin
username admin passphrase lifetime 99999 warntime 14 gracetime 3
username oper password 5 $5$Pa55w0rd role network-operator
username admin sshkey ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC admin@host
tacacs-server key 7 "Pa55w0rd"
tacacs-server host 10.0.0.5 key 7 "Pa55w0rd"
radius-server key 7 "Pa55w0rd"
radius-server host 10.0.0.6 key 7 "Pa55w0rd" authentication accounting
aaa group server tacacs+ TACGRP
  server 10.0.0.5
  use-vrf management
  source-interface mgmt0
aaa authentication login default group TACGRP
key chain BGP-KC
  key 1
    key-string 7 Pa55w0rd
    accept-lifetime 00:00:00 Jan 01 2020 infinite
    send-lifetime 00:00:00 Jan 01 2020 infinite
  key 2
    key-string 7 k3y
    cryptographic-algorithm HMAC-SHA-256
key chain MACSEC-KC macsec
  key 1000
    key-octet-string 7 Pa55w0rd cryptographic-algorithm AES_256_CMAC
    send-lifetime 00:00:00 Jan 01 2020 infinite
ip domain-lookup
snmp-server contact noc@example.com
snmp-server location Belgrade DC1 rack 12
snmp-server user admin network-admin auth md5 0x1234Pa55w0rd priv 0x5678Pa55w0rd localizedkey
snmp-server user admin auth md5 Pa55w0rd priv aes-128 Pa55w0rd
snmp-server host 192.0.2.9 traps version 2c c0mmun1ty
snmp-server host 192.0.2.9 use-vrf management
snmp-server host 192.0.2.9 source-interface mgmt0
snmp-server host 192.0.2.10 informs version 3 priv snmpuser
snmp-server community c0mmun1ty group network-operator
snmp-server community c0mmun1ty use-ipv4acl ACL-SNMP
snmp-server enable traps bgp
ntp server 192.0.2.1 key 1 use-vrf management prefer
ntp server 192.0.2.2 use-vrf management
ntp peer 192.0.2.3 key 1
ntp authentication-key 1 md5 Pa55w0rd 7
ntp authenticate
ntp trusted-key 1
ntp source-interface mgmt0
vlan 1,10,20
vlan 10
  name Servers-key-account
vrf context management
  ip route 0.0.0.0/0 10.10.10.254
interface Vlan10
  description Servers key account
  no shutdown
  no ip redirects
  ip address 10.10.10.1/24
  hsrp 10
    authentication md5 key-string 7 Pa55w0rd
    authentication md5 key-chain HSRP-KC
    authentication text Pa55w0rd
    ip 10.10.10.3
  vrrp 20
    authentication text Pa55w0rd
    address 10.10.10.4
  vrrpv3 30 address-family ipv4
    address 10.10.10.5 primary
interface port-channel1
  description vPC peer-link key account
  switchport mode trunk
interface Ethernet1/1
  description Uplink to CORE key account
  no switchport
  ip address 10.1.1.1/30
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 7 Pa55w0rd
  ip ospf authentication-key 7 Pa55w0rd
  ip ospf authentication key-chain OSPF-KC
  ip router ospf 1 area 0.0.0.0
  macsec keychain MACSEC-KC policy MACSEC-P
  no shutdown
interface Ethernet1/2
  description to firewall
  switchport access vlan 10
interface mgmt0
  description OOB key access
  vrf member management
  ip address 10.10.10.2/24
interface loopback0
  description Key Account loopback
  ip address 10.255.0.1/32
interface nve1
  description VXLAN key
  source-interface loopback0
  host-reachability protocol bgp
router ospf 1
  router-id 10.255.0.1
  area 0.0.0.0 authentication message-digest
router bgp 65000
  router-id 10.255.0.1
  neighbor 10.255.0.2
    remote-as 65000
    description iBGP to PE2 key account
    password 3 Pa55w0rd
    update-source loopback0
    address-family ipv4 unicast
      send-community
      send-community extended
  neighbor 10.255.0.3
    remote-as 65000
    authentication key-chain BGP-KC
vpc domain 10
  peer-keepalive destination 10.10.10.2 source 10.10.10.1 vrf management
  peer-switch
  peer-gateway
boot nxos bootflash:/nxos64-cs.10.2.3.F.bin
line vty
  exec-timeout 30
banner motd #
Authorized access only. Key personnel only.
#
macsec policy MACSEC-P
  cipher-suite GCM-AES-XPN-256
  key-server-priority 0
  sak-expiry-time 60
  include-icv-indicator
cfs eth distribute
""",
    "Junos": """\
## Last commit: 2024-01-01 00:00:00 UTC by admin
version 21.4R3.15;
system {
    host-name MX-1;
    root-authentication {
        encrypted-password "$6$S3CRET"; ## SECRET-DATA
        ssh-rsa "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB root@host"; ## SECRET-DATA
    }
    login {
        user admin {
            uid 2000;
            class super-user;
            authentication {
                encrypted-password "$6$Pa55w0rd"; ## SECRET-DATA
            }
        }
        user oper {
            uid 2001;
            class read-only;
            authentication {
                ssh-rsa "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB oper@host"; ## SECRET-DATA
            }
        }
        message "Authorized access only. Key personnel. Secret.";
    }
    authentication-order [ password radius ];
    radius-server {
        10.0.0.6 {
            secret "$9$Pa55w0rd"; ## SECRET-DATA
            source-address 10.10.10.3;
        }
    }
    tacplus-server {
        10.0.0.5 secret "$9$Pa55w0rd"; ## SECRET-DATA
    }
    services {
        ssh {
            root-login deny;
            protocol-version v2;
            ciphers [ aes256-ctr aes256-gcm@openssh.com ];
            macs [ hmac-sha2-256 hmac-sha2-512 ];
            key-exchange [ ecdh-sha2-nistp256 ];
        }
        netconf {
            ssh;
        }
    }
    ntp {
        authentication-key 1 type md5 value "$9$Pa55w0rd"; ## SECRET-DATA
        server 192.0.2.1 key 1 prefer;
        server 192.0.2.2 routing-instance MGMT;
        peer 192.0.2.3 key 1;
        trusted-key 1;
        source-address 10.255.0.1;
    }
    archival {
        configuration {
            transfer-on-commit;
            archive-sites {
                "scp://admin:p@ss/w0rd@10.0.0.1/backups" password "$9$Pa55w0rd"; ## SECRET-DATA
                "ftp://10.0.0.1:21/backups@site";
            }
        }
    }
}
security {
    authentication-key-chains {
        key-chain ISIS-KC {
            key 1 {
                secret "$9$Pa55w0rd"; ## SECRET-DATA
                start-time "2020-1-1.00:00:00 +0000";
                algorithm hmac-sha-1;
            }
        }
    }
    ike {
        proposal P1 {
            authentication-method pre-shared-keys;
            dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc;
        }
        policy IKE-POL {
            mode main;
            proposals P1;
            pre-shared-key ascii-text "$9$Pa55w0rd"; ## SECRET-DATA
        }
    }
}
interfaces {
    ge-0/0/0 {
        description "Uplink to CORE - key account";
        unit 0 {
            family inet {
                address 10.1.1.1/30;
            }
            family iso;
            family mpls;
        }
    }
    ge-0/0/1 {
        description "jump host passwd: Welcome123";
        unit 0 {
            family inet;
        }
    }
    lo0 {
        description "Key Account loopback";
        unit 0 {
            family inet {
                address 10.255.0.1/32;
            }
        }
    }
    fxp0 {
        description "OOB key";
        unit 0 {
            family inet {
                address 10.10.10.3/24;
            }
        }
    }
    irb {
        unit 100 {
            description "Servers key account";
            family inet {
                address 10.10.10.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.10.10.4;
                        authentication-type md5;
                        authentication-key "$9$Pa55w0rd"; ## SECRET-DATA
                    }
                }
            }
        }
    }
}
snmp { ## Warning: 'snmp' is deprecated
    location "Belgrade DC1 rack 12";
    contact "noc@example.com";
    community c0mmun1ty {
        authorization read-only;
        clients {
            192.0.2.0/24;
        }
    }
    community "c0mmun1ty rw" {
        authorization read-write;
    }
    trap-group NOC {
        version v2;
        targets {
            192.0.2.9;
        }
    }
    v3 {
        usm {
            local-engine {
                user snmpuser {
                    authentication-sha {
                        authentication-key "$9$Pa55w0rd"; ## SECRET-DATA
                    }
                    privacy-aes128 {
                        privacy-key "$9$Pa55w0rd"; ## SECRET-DATA
                    }
                }
            }
        }
    }
}
policy-options {
    policy-statement EXPORT-VRF-A {
        term 1 {
            then {
                community add VRF-A-RT;
                accept;
            }
        }
    }
    policy-statement IMPORT-VRF-A {
        term 1 {
            from community VRF-A-RT;
            then accept;
        }
    }
    community VRF-A-RT members target:65000:100;
    community SNMP-MGMT-RT members target:65000:999;
}
protocols {
    bgp {
        group IBGP {
            type internal;
            local-address 10.255.0.1;
            authentication-key "$9$Pa55w0rd"; ## SECRET-DATA
            authentication-key-chain BGP-KC;
            family inet-vpn {
                unicast;
            }
            neighbor 10.255.0.2 {
                description "iBGP to PE2 key account";
            }
        }
    }
    isis {
        level 2 {
            authentication-key "$9$Pa55w0rd"; ## SECRET-DATA
            authentication-type md5;
            authentication-key-chain ISIS-KC;
        }
        interface ge-0/0/0.0 {
            point-to-point;
            level 2 hello-authentication-key-chain ISIS-KC;
        }
        interface lo0.0 {
            passive;
        }
    }
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                authentication {
                    md5 1 key "$9$Pa55w0rd"; ## SECRET-DATA
                }
            }
        }
    }
    ldp {
        interface ge-0/0/0.0;
        session 10.255.0.2 {
            authentication-key "$9$Pa55w0rd"; ## SECRET-DATA
        }
    }
    rsvp {
        interface ge-0/0/0.0 {
            authentication-key "$9$Pa55w0rd"; ## SECRET-DATA
        }
    }
    lldp {
        interface all;
    }
}
routing-instances {
    VRF-A {
        instance-type vrf;
        interface irb.100;
        route-distinguisher 65000:100;
        vrf-target target:65000:100;
        vrf-table-label;
    }
    MGMT {
        instance-type virtual-router;
        interface fxp0.0;
    }
}
""",
    "ASA": """\
: Saved
ASA Version 9.16(4)
!
hostname ASA-1
domain-name example.com
enable password $sha512$5000$S3CRET pbkdf2
passwd Pa55w0rd encrypted
names
no mac-address auto
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 description Inside - key account LAN
 nameif inside
 security-level 100
 ip address 10.10.10.254 255.255.255.0
!
interface Management0/0
 management-only
 nameif management
 security-level 100
 ip address 10.10.20.1 255.255.255.0
!
banner motd (c) Example Corp. Authorized access only.
banner motd !!! WARNING: key personnel only !!!
banner exec Welcome
banner login Secret stuff inside
ftp mode passive
object network INSIDE-NET
 subnet 10.10.10.0 255.255.255.0
 description Key Account LAN
object-group network KEY-SERVERS
 description key servers
 network-object host 10.10.10.5
access-list OUTSIDE_IN extended permit tcp any host 203.0.113.5 eq https
nat (inside,outside) source dynamic INSIDE-NET interface
access-group OUTSIDE_IN in interface outside
route outside 0.0.0.0 0.0.0.0 203.0.113.254 1
aaa-server TACGRP protocol tacacs+
aaa-server TACGRP (inside) host 10.0.0.5
 key Pa55w0rd
 timeout 5
aaa-server RADGRP protocol radius
aaa-server RADGRP (inside) host 10.0.0.6
 key Pa55w0rd
 radius-common-pw Pa55w0rd
 authentication-port 1812
aaa authentication ssh console TACGRP LOCAL
aaa authentication enable console TACGRP LOCAL
user-identity default-domain LOCAL
http server enable
http 10.10.20.0 255.255.255.0 management
snmp-server host inside 192.0.2.9 community c0mmun1ty version 2c
snmp-server host inside 192.0.2.9 poll community c0mmun1ty version 2c udp-port 161
snmp-server host inside 192.0.2.10 trap community 0 c0mmun1ty version 2c
snmp-server host management 192.0.2.11 version 3 snmpuser
snmp-server host management 2001:db8::9 community c0mmun1ty
snmp-server host inside 192.0.2.12 poll
snmp-server host inside 192.0.2.13
snmp-server host-group inside NMS-GRP community c0mmun1ty version 2c
snmp-server user snmpuser SNMP-GRP v3 engineID 8000000 encrypted auth sha Pa55w0rd priv aes 128 Pa55w0rd
snmp-server group SNMP-GRP v3 priv
snmp-server location Belgrade DC1 rack 12
snmp-server contact noc@example.com
snmp-server community c0mmun1ty
snmp-server enable traps snmp authentication linkup linkdown coldstart
crypto ipsec ikev1 transform-set TS esp-aes-256 esp-sha-hmac
crypto ipsec ikev2 ipsec-proposal AES256
 protocol esp encryption aes-256
 protocol esp integrity sha-1
crypto map CMAP 10 match address VPN-ACL
crypto map CMAP 10 set peer 192.0.2.1
crypto map CMAP 10 set ikev1 transform-set TS
crypto map CMAP interface outside
crypto ca trustpoint CA
 enrollment url http://ca.example.com:80/certsrv/mscep/mscep.dll
 keypair KEY
 crl configure
crypto ikev1 enable outside
crypto ikev1 policy 10
 authentication pre-share
 encryption aes-256
 hash sha
 group 14
 lifetime 86400
crypto ikev1 policy 20
 authentication rsa-sig
 encryption aes
 hash sha
 group 5
crypto ikev1 policy 30
 authentication crack
 encryption aes
 hash sha
 group 5
crypto ikev2 policy 1
 encryption aes-256
 integrity sha256
 group 14
 prf sha256
 lifetime seconds 86400
crypto ikev2 enable outside
telnet timeout 5
ssh stricthostkeycheck
ssh 10.10.20.0 255.255.255.0 management
ssh timeout 30
ssh version 2
ssh key-exchange group dh-group14-sha256
ssh cipher encryption high
console timeout 0
ntp authentication-key 1 md5 Pa55w0rd
ntp authenticate
ntp trusted-key 1
ntp server 192.0.2.1 key 1 source inside prefer
ntp server 192.0.2.2 source inside
dhcpd address 10.10.10.100-10.10.10.200 inside
threat-detection basic-threat
tunnel-group 192.0.2.1 type ipsec-l2l
tunnel-group 192.0.2.1 ipsec-attributes
 ikev1 pre-shared-key Pa55w0rd
 ikev2 remote-authentication pre-shared-key Pa55w0rd
 ikev2 local-authentication pre-shared-key Pa55w0rd
tunnel-group RA type remote-access
tunnel-group RA general-attributes
 address-pool VPN-POOL
 authentication-server-group RADGRP
tunnel-group RA webvpn-attributes
 group-alias RA enable
username admin password $sha512$5000$Pa55w0rd pbkdf2 privilege 15
username admin attributes
 service-type admin
username vpnuser password Pa55w0rd encrypted
failover
failover lan unit primary
failover lan interface FO GigabitEthernet0/3
failover key Pa55w0rd
failover ipsec pre-shared-key Pa55w0rd
failover link FO GigabitEthernet0/3
failover interface ip FO 203.0.113.249 255.255.255.252 standby 203.0.113.250
logging host inside 10.10.10.50
webvpn
 enable outside
 anyconnect image disk0:/anyconnect.pkg 1
 anyconnect enable
group-policy GP internal
group-policy GP attributes
 vpn-tunnel-protocol ikev2 ssl-client
 webvpn
  anyconnect keep-installer installed
Cryptochecksum:0123456789abcdef0123456789abcdef
: end
""",
    "OPERATIONAL": """\
Interface                      Status         Protocol Description
Gi1                            up             up       Uplink to CORE key account
Gi2                            admin down     down     secret link to lab
Lo0                            up             up       Key Account loopback
Vl10                           up             up       Servers key account
Tu0                            up             up       DMVPN key tunnel
Po1                            up             up       vPC peer-link key account
Te1/0/1                        up             up       key access
Twe1/0/1                       up             up       key access 25G
Fo1/0/1                        up             up       key access 40G
Hu1/0/1                        up             up       key access 100G
Ap1/0/1                        up             up       key app
Bl1/0/1                        up             up       key bluetooth
BD10                           up             up       key bdi
Nu0                            up             up       key null
Interface          Status      Protocol    Description
--------------------------------------------------------------------------------
Lo0                up          up          Key Account loopback
Mg0/RP0/CPU0/0     up          up          OOB key mgmt
Gi0/0/0/0          up          up          Key Account uplink
BE1                up          up          Key Account bundle
tt1                up          up          key te tunnel
Nu0                up          up          key null
-------------------------------------------------------------------------------
Interface                Description
-------------------------------------------------------------------------------
mgmt0                    OOB key mgmt
Vlan10                   Servers key account
-------------------------------------------------------------------------------
Port          Type   Speed   Description
-------------------------------------------------------------------------------
Eth1/1        eth    10G     Uplink to CORE key account
Eth1/2        eth    1000    to firewall secret
Po1           eth    10G     vPC peer-link key
nve1          eth    --      VXLAN key
Lo0           eth    --      Key Account loopback
Interface       Admin Link Description
ge-0/0/0        up    up   Uplink to CORE - key account
ge-0/0/0.0      up    up   Uplink unit key
lo0             up    up   Key Account loopback
fxp0            up    up   OOB key
irb.100         up    up   Servers key account
ae0             up    up   LAG key
et-0/0/0        up    up   100G key
xe-0/0/1        up    up   10G key
em0             up    up   mgmt key
RP/0/RP0/CPU0:PE-XR#show interfaces description
Interface          Status      Protocol    Description
--------------------------------------------------------------------------------
MgmtEth0/RP0/CPU0/0 up         up          OOB key mgmt
Gi0/0/0/1          up          up          Key Account core
PT0/RP0/CPU0/0     admin-down  admin-down  key timing port
Gi0/0/0/2          up          up          Key Account access
pw-ether1          up          up          Key Account pseudowire headend
SR-TE1             up          up          Key Account policy
ti0/0/0/0          up          up          key tunnel-ip
BE2                up          up          Key Account bundle
Gi0/0/0/3          up          up          lab link password Welcome123
RP/0/RP0/CPU0:PE-XR#show running-config router bgp
router bgp 65000
 neighbor 10.255.0.2
  password encrypted 0123Pa55w0rd
R1#show running-config | include key
 key 7 Pa55w0rd
R1#show ip arp
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.1.1.2                0   0011.2233.4455  ARPA   GigabitEthernet1
R1#show cdp neighbors detail
Device ID: SW1.example.com
Entry address(es):
  IP address: 10.0.0.5
Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP
Interface: GigabitEthernet1,  Port ID (outgoing port): GigabitEthernet1/0/1
Version :
Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4, RELEASE SOFTWARE (fc5)
Management address(es):
  IP address: 10.0.0.5
R1#show version
Cisco IOS XE Software, Version 17.09.04a
System image file is "bootflash:packages.conf"
License Level: network-advantage
Technology Package License Information:
Processor board ID 9ABCDEFGHIJ
cisco C8300-1N1S-4T2X (1RU) processor with 3763327K/6147K bytes of memory.
Configuration register is 0x2102
RP/0/RP0/CPU0:PE-XR#show lldp neighbors detail
Local Interface: GigabitEthernet0/0/0/0
Chassis id: 0011.2233.4455
Port id: Gi1/0/1
Port Description: key access
System Name: SW1
System Description: Cisco IOS Software, Key Account build
System Capabilities: B,R
Enabled Capabilities: B
Management Addresses:
  IPv4 address: 10.0.0.5
N9K-1# show bgp sessions
Neighbor        ASN    Flaps LastUpDn|LastRead|LastWrit St Port(L/R)  Notif(S/R)
10.255.0.2      65000  0     1w2d    |never   |never    E  179/42312   0/0
Password: *****
Password:
password check failed
Login incorrect: bad password
admin@MX-1> show configuration snmp | display set
set snmp location "Belgrade DC1 rack 12"
set snmp community c0mmun1ty authorization read-only
set snmp community c0mmun1ty clients 192.0.2.0/24
set snmp community "c0mmun1ty rw" authorization read-write
set snmp trap-group NOC targets 192.0.2.9
set policy-options community VRF-A-RT members target:65000:100
admin@MX-1> show configuration snmp
snmp { /* NOC */
    community c0mmun1ty;
}
community VRF-A-RT members target:65000:100;
R1#show running-config | include snmp
\x1b[Ksnmp-server community c0mmun1ty RO
 --More-- \x08\x08\x08\x08\x08\x08\x08\x08\x08\x08          \x08\x08\x08\x08\x08\x08\x08\x08\x08\x08snmp-server community c0mmun1ty RW
\x00snmp-server host 192.0.2.9 version 2c c0mmun1ty
""",
}

EXPECTED = {
    "IOS-XE": """\
version 17.9
service password-encryption
hostname PE1
boot-start-marker
enable secret <REDACTED BY DISCONET>
enable password <REDACTED BY DISCONET>
username admin privilege 15 secret <REDACTED BY DISCONET>
username oper password <REDACTED BY DISCONET>
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
tacacs server TAC1
 address ipv4 10.0.0.5
 key <REDACTED BY DISCONET>
 timeout 5
radius server RAD1
 address ipv4 10.0.0.6 auth-port 1812 acct-port 1813
 key <REDACTED BY DISCONET>
aaa group server tacacs+ TACGRP
 server name TAC1
 server-private 10.0.0.7 key <REDACTED BY DISCONET>
key chain ISIS-KC
 key 1
  key-string <REDACTED BY DISCONET>
  cryptographic-algorithm hmac-sha-256
  accept-lifetime 00:00:00 Jan 1 2020 infinite
 key 2
  key-string <REDACTED BY DISCONET>
key chain MACSEC-KC macsec
 key 01
  cryptographic-algorithm aes-128-cmac
  key-string <REDACTED BY DISCONET>
crypto isakmp policy 10
 encr aes 256
 authentication pre-share
 group 14
crypto isakmp policy 20
 authentication rsa-encr
 group 14
crypto isakmp policy 30
 authentication ecdsa-sig
 group 19
crypto isakmp key <REDACTED BY DISCONET> address 192.0.2.1
crypto isakmp key <REDACTED BY DISCONET>
crypto keyring KR
 pre-shared-key address 192.0.2.2 key <REDACTED BY DISCONET>
crypto ikev2 keyring IKEV2-KR
 peer HUB
  address 192.0.2.3
  pre-shared-key <REDACTED BY DISCONET>
  pre-shared-key <REDACTED BY DISCONET>
crypto ikev2 profile IKEV2-P
 match identity remote address 192.0.2.3 255.255.255.255
 authentication remote pre-share
 authentication local pre-share
 keyring local IKEV2-KR
crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac
 mode tunnel
crypto ipsec profile IPSEC-P
 set transform-set TS
interface Loopback0
 description Key Account loopback for S3CRET-customer
 ip address 10.255.0.1 255.255.255.255
interface GigabitEthernet1
 description Uplink to CORE password <REDACTED BY DISCONET>
 ip address 10.1.1.1 255.255.255.252
 ip ospf message-digest-key <REDACTED BY DISCONET>
 ip ospf authentication message-digest
 ip ospf authentication key-chain OSPF-KC
 ip rip authentication key-chain RIP-KC
 ip rip authentication mode md5
 isis authentication mode md5 level-2
 isis authentication key-chain ISIS-KC level-2
 standby 1 ip 10.1.1.3
 standby 1 authentication text <REDACTED BY DISCONET>
 standby 1 authentication <REDACTED BY DISCONET>
 standby 1 authentication md5 key-chain HSRP-KC
 vrrp 2 authentication text <REDACTED BY DISCONET>
 glbp 3 authentication <REDACTED BY DISCONET>
 ip nhrp authentication <REDACTED BY DISCONET>
 ip nhrp map multicast dynamic
 tunnel protection ipsec profile IPSEC-P
interface Vlan10
 description Mgmt - key account
 ip address 10.10.10.1 255.255.255.0
interface Vlan20
 description guest wifi password <REDACTED BY DISCONET>
 ip address 10.10.20.1 255.255.255.0
router ospf 1
 router-id 10.255.0.1
 area 0 authentication message-digest
router isis CORE
 net 49.0001.0100.2550.0001.00
 authentication mode md5 level-2
 authentication key-chain ISIS-KC level-2
 lsp-password keychain X
router bgp 65000
 neighbor 10.255.0.2 remote-as 65000
 neighbor 10.255.0.2 password <REDACTED BY DISCONET>
 neighbor 10.255.0.2 description iBGP to PE2 key account
 neighbor 10.255.0.2 update-source Loopback0
 address-family ipv4
  neighbor 10.255.0.2 activate
  neighbor 10.255.0.2 send-community both
 address-family vpnv4
  neighbor 10.255.0.2 send-community extended
ip route 0.0.0.0 0.0.0.0 10.1.1.2
snmp-server community <REDACTED BY DISCONET>
snmp-server community <REDACTED BY DISCONET>
snmp-server community-map <REDACTED BY DISCONET>
snmp-server location Belgrade DC1 rack 12
snmp-server contact noc@example.com
snmp-server host 192.0.2.9 version 2c <REDACTED BY DISCONET>
snmp-server host 192.0.2.9 informs version 3 auth <REDACTED BY DISCONET>
snmp-server host nms.example.com <REDACTED BY DISCONET>
snmp-server host nms.example.com <REDACTED BY DISCONET>
snmp-server host nms.example.com <REDACTED BY DISCONET>
snmp-server host nms.example.com <REDACTED BY DISCONET>
snmp-server host nms.example.com <REDACTED BY DISCONET>
snmp-server host nms.example.com traps version 2c <REDACTED BY DISCONET>
snmp-server host 2001:db8::9 version 2c <REDACTED BY DISCONET>
snmp-server host 192.0.2.9 vrf MGMT version 2c <REDACTED BY DISCONET>
snmp-server user snmpuser GRP v3 auth sha <REDACTED BY DISCONET>
snmp-server group GRP v3 priv
snmp-server view ALL iso included
snmp-server trap-source Loopback0
snmp-server enable traps bgp
ntp authentication-key <REDACTED BY DISCONET>
ntp authenticate
ntp trusted-key 1
ntp server 192.0.2.1 key 1 prefer source Loopback0
ntp server vrf MGMT 192.0.2.2 key 2
ntp peer 192.0.2.3 key 1
ntp server 192.0.2.4
archive
 path scp://<REDACTED BY DISCONET>@10.0.0.1/backups/$h-$t
 path tftp://10.0.0.1:69/cfg@site
 path ftp://<REDACTED BY DISCONET>@10.0.0.1/cfg
 path scp://<REDACTED BY DISCONET>@10.0.0.1/cfg
 path scp://<REDACTED BY DISCONET>@10.0.0.1/cfg
 path ftp://<REDACTED BY DISCONET>@10.0.0.1/cfg
 path scp://<REDACTED BY DISCONET>@10.0.0.1/cfg
 path flash:/archive
ip http client username admin
ip http client password <REDACTED BY DISCONET>
ip ssh server algorithm mac hmac-sha2-256
ip ssh server algorithm encryption aes256-ctr
crypto pki trustpoint CA
 enrollment url http://ca.example.com:80/certsrv
 enrollment url http://ca.example.com:80/certsrv/mscep/mscep.dll@site
 password <REDACTED BY DISCONET>
 subject-name CN=PE1
dot11 ssid CORP
 authentication open
 authentication shared
 authentication key-management wpa version 2
 wpa-psk ascii 7 <REDACTED BY DISCONET>
interface GigabitEthernet1/0/1
 description access port key card readers
 switchport mode access
 authentication port-control auto
 authentication open
 authentication periodic
 authentication order dot1x mab
 authentication host-mode multi-auth
 authentication violation restrict
 authentication event fail action next-method
 authentication timer reauthenticate server
 dot1x pae authenticator
 mab
line vty 0 4
 password <REDACTED BY DISCONET>
 login local
 transport input ssh
banner motd ^C
Authorized access only. Key personnel: NOC. Secret <REDACTED BY DISCONET>
^C
mpls ldp neighbor 10.255.0.2 password <REDACTED BY DISCONET>
mpls ldp password required
mpls ldp password <REDACTED BY DISCONET>
router ospfv3 1
 area 0 authentication ipsec spi 500 sha1 <REDACTED BY DISCONET>
 area 1 encryption ipsec spi 501 esp aes-cbc 128 <REDACTED BY DISCONET>
 area 2 encryption ipsec spi 502 esp null <REDACTED BY DISCONET>
ipv6 ospf authentication ipsec spi 256 md5 <REDACTED BY DISCONET>
macsec
mka policy MKA
 key-server priority 10
 macsec-cipher-suite gcm-aes-256
mka pre-shared-key key-chain MACSEC-KC
username bob password <REDACTED BY DISCONET>
username carol password <REDACTED BY DISCONET>
crypto pki token <REDACTED BY DISCONET>
crypto pki token <REDACTED BY DISCONET>
parameter-map type umbrella global
 token <REDACTED BY DISCONET>
 local-domain LOCAL-DOMAINS
license smart trust idtoken <REDACTED BY DISCONET>
event manager environment _password <REDACTED BY DISCONET>
event manager environment _email_password <REDACTED BY DISCONET>
event manager environment _secret <REDACTED BY DISCONET>
event manager environment _key <REDACTED BY DISCONET>
event manager environment _login_pw <REDACTED BY DISCONET>
event manager applet ROTATE
 event timer cron cron-entry "0 3 * * *"
 action 1.0 cli command "enable" pattern "[Pp]assword"
 action 1.1 cli command "<REDACTED BY DISCONET>"
 action 2.0 cli command "configure terminal"
 action 3.0 cli command "snmp-server community <REDACTED BY DISCONET>"
 action 4.0 cli command "snmp-server host 192.0.2.9 version 2c <REDACTED BY DISCONET>"
 action 5.0 cli command "username u secret <REDACTED BY DISCONET>"
 action 6.0 cli command "end"
""",
    "IOS-XR": """\
hostname PE-XR
username admin
 group root-lr
 secret <REDACTED BY DISCONET>
 password <REDACTED BY DISCONET>
!
tacacs-server host 10.0.0.5 port 49
 key <REDACTED BY DISCONET>
!
radius-server host 10.0.0.6 auth-port 1812 acct-port 1813
 key <REDACTED BY DISCONET>
!
key chain ISIS-KC
 key 1
  accept-lifetime 00:00:00 january 01 2020 infinite
  key-string <REDACTED BY DISCONET>
  send-lifetime 00:00:00 january 01 2020 infinite
  cryptographic-algorithm HMAC-MD5
 !
 key 2
  key-string <REDACTED BY DISCONET>
 !
!
key chain BGP-KC
 key 1
  key-string <REDACTED BY DISCONET>
  cryptographic-algorithm HMAC-SHA1-20
!
ntp
 authentication-key <REDACTED BY DISCONET>
 authenticate
 trusted-key 1
 server 192.0.2.1 key 1 prefer
 server vrf MGMT 192.0.2.2 key 1
 peer 192.0.2.3 key 1
 source Loopback0
 update-calendar
!
interface Loopback0
 description Key Account loopback
 ipv4 address 10.255.0.1 255.255.255.255
!
interface MgmtEth0/RP0/CPU0/0
 description OOB management key
 ipv4 address 10.10.10.2 255.255.255.0
!
interface GigabitEthernet0/0/0/0
 description Uplink to CORE - key account
 ipv4 address 10.1.1.1 255.255.255.252
!
router static
 address-family ipv4 unicast
  0.0.0.0/0 10.1.1.2
 !
!
router isis CORE
 net 49.0001.0100.2550.0001.00
 lsp-password keychain ISIS-KC
 lsp-password hmac-md5 encrypted <REDACTED BY DISCONET> level 2
 lsp-password keychain ISIS-KC level 1
 address-family ipv4 unicast
  metric-style wide
  segment-routing mpls
 !
 interface GigabitEthernet0/0/0/0
  hello-password keychain ISIS-KC level 2
  hello-password hmac-md5 encrypted <REDACTED BY DISCONET>
  hello-password keychain ISIS-KC
  point-to-point
 !
!
router ospf 1
 router-id 10.255.0.1
 area 0
  authentication message-digest
  authentication keychain OSPF-KC
  message-digest-key <REDACTED BY DISCONET>
  authentication-key <REDACTED BY DISCONET>
  interface GigabitEthernet0/0/0/0
   authentication
   authentication null
  !
 !
!
router ospfv3 1
 area 1
  authentication disable
 !
 area 0
  authentication ipsec spi 500 sha1 <REDACTED BY DISCONET>
  encryption ipsec spi 501 esp aes 192 <REDACTED BY DISCONET>
  encryption ipsec spi 502 esp 3des <REDACTED BY DISCONET>
 !
!
router bgp 65000
 bgp router-id 10.255.0.1
 address-family ipv4 unicast
 !
 neighbor 10.255.0.2
  remote-as 65000
  password <REDACTED BY DISCONET>
  keychain BGP-KC
  description iBGP to PE2 key account
  update-source Loopback0
  address-family ipv4 unicast
  !
 !
!
router hsrp
 interface GigabitEthernet0/0/0/1
  address-family ipv4
   hsrp 1
    authentication <REDACTED BY DISCONET>
    address 192.0.2.123
    priority 110
   !
  !
 !
!
router vrrp
 interface GigabitEthernet0/0/0/1
  address-family ipv4
   vrrp 2
    text-authentication <REDACTED BY DISCONET>
   !
  !
 !
!
snmp-server community <REDACTED BY DISCONET>
snmp-server community-map <REDACTED BY DISCONET>
snmp-server host 192.0.2.9 traps version 2c <REDACTED BY DISCONET>
snmp-server host 192.0.2.9 traps version 3 priv <REDACTED BY DISCONET>
snmp-server vrf MGMT
 host 192.0.2.10 traps version 2c <REDACTED BY DISCONET>
 host 192.0.2.11 informs version 2c <REDACTED BY DISCONET>
 host 192.0.2.12 <REDACTED BY DISCONET>
 host 192.0.2.13 <REDACTED BY DISCONET>
!
snmp-server user snmpuser GRP v3 auth sha <REDACTED BY DISCONET>
snmp-server location Belgrade DC1 rack 12
snmp-server contact noc@example.com
snmp-server trap-source Loopback0
snmp-server traps bgp
mpls ldp
 router-id 10.255.0.1
 neighbor 10.255.0.2:0 password <REDACTED BY DISCONET>
 neighbor password <REDACTED BY DISCONET>
 interface GigabitEthernet0/0/0/0
 !
!
ssh server v2
ssh server algorithms key-exchange ecdh-sha2-nistp256
ssh server algorithms cipher aes256-ctr
ssh server algorithms hostkey ecdsa-nistp256
ssh server vrf MGMT
banner motd #
Authorized access only. Key personnel only. Secret.
#
aaa authentication login default group TACGRP local
aaa group server tacacs+ TACGRP
 server 10.0.0.5
 server-private 10.0.0.7 port 49
  key <REDACTED BY DISCONET>
 !
!
lpts pifib hardware police
 flow bgp known rate 2500
!
""",
    "NX-OS": """\
version 10.2(3)
hostname N9K-1
feature bgp
feature ospf
feature interface-vlan
feature lldp
feature nxapi
username admin password <REDACTED BY DISCONET>
username admin passphrase lifetime 99999 warntime 14 gracetime 3
username oper password <REDACTED BY DISCONET>
username admin sshkey ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC admin@host
tacacs-server key <REDACTED BY DISCONET>
tacacs-server host 10.0.0.5 key <REDACTED BY DISCONET>
radius-server key <REDACTED BY DISCONET>
radius-server host 10.0.0.6 key <REDACTED BY DISCONET>
aaa group server tacacs+ TACGRP
  server 10.0.0.5
  use-vrf management
  source-interface mgmt0
aaa authentication login default group TACGRP
key chain BGP-KC
  key 1
    key-string <REDACTED BY DISCONET>
    accept-lifetime 00:00:00 Jan 01 2020 infinite
    send-lifetime 00:00:00 Jan 01 2020 infinite
  key 2
    key-string <REDACTED BY DISCONET>
    cryptographic-algorithm HMAC-SHA-256
key chain MACSEC-KC macsec
  key 1000
    key-octet-string 7 <REDACTED BY DISCONET>
    send-lifetime 00:00:00 Jan 01 2020 infinite
ip domain-lookup
snmp-server contact noc@example.com
snmp-server location Belgrade DC1 rack 12
snmp-server user admin network-admin auth md5 <REDACTED BY DISCONET>
snmp-server user admin auth md5 <REDACTED BY DISCONET>
snmp-server host 192.0.2.9 traps version 2c <REDACTED BY DISCONET>
snmp-server host 192.0.2.9 use-vrf management
snmp-server host 192.0.2.9 source-interface mgmt0
snmp-server host 192.0.2.10 informs version 3 priv <REDACTED BY DISCONET>
snmp-server community <REDACTED BY DISCONET>
snmp-server community <REDACTED BY DISCONET>
snmp-server enable traps bgp
ntp server 192.0.2.1 key 1 use-vrf management prefer
ntp server 192.0.2.2 use-vrf management
ntp peer 192.0.2.3 key 1
ntp authentication-key <REDACTED BY DISCONET>
ntp authenticate
ntp trusted-key 1
ntp source-interface mgmt0
vlan 1,10,20
vlan 10
  name Servers-key-account
vrf context management
  ip route 0.0.0.0/0 10.10.10.254
interface Vlan10
  description Servers key account
  no shutdown
  no ip redirects
  ip address 10.10.10.1/24
  hsrp 10
    authentication md5 <REDACTED BY DISCONET>
    authentication md5 key-chain HSRP-KC
    authentication text <REDACTED BY DISCONET>
    ip 10.10.10.3
  vrrp 20
    authentication text <REDACTED BY DISCONET>
    address 10.10.10.4
  vrrpv3 30 address-family ipv4
    address 10.10.10.5 primary
interface port-channel1
  description vPC peer-link key account
  switchport mode trunk
interface Ethernet1/1
  description Uplink to CORE key account
  no switchport
  ip address 10.1.1.1/30
  ip ospf authentication message-digest
  ip ospf message-digest-key <REDACTED BY DISCONET>
  ip ospf authentication-key <REDACTED BY DISCONET>
  ip ospf authentication key-chain OSPF-KC
  ip router ospf 1 area 0.0.0.0
  macsec keychain MACSEC-KC policy MACSEC-P
  no shutdown
interface Ethernet1/2
  description to firewall
  switchport access vlan 10
interface mgmt0
  description OOB key access
  vrf member management
  ip address 10.10.10.2/24
interface loopback0
  description Key Account loopback
  ip address 10.255.0.1/32
interface nve1
  description VXLAN key
  source-interface loopback0
  host-reachability protocol bgp
router ospf 1
  router-id 10.255.0.1
  area 0.0.0.0 authentication message-digest
router bgp 65000
  router-id 10.255.0.1
  neighbor 10.255.0.2
    remote-as 65000
    description iBGP to PE2 key account
    password <REDACTED BY DISCONET>
    update-source loopback0
    address-family ipv4 unicast
      send-community
      send-community extended
  neighbor 10.255.0.3
    remote-as 65000
    authentication key-chain BGP-KC
vpc domain 10
  peer-keepalive destination 10.10.10.2 source 10.10.10.1 vrf management
  peer-switch
  peer-gateway
boot nxos bootflash:/nxos64-cs.10.2.3.F.bin
line vty
  exec-timeout 30
banner motd #
Authorized access only. Key personnel only.
#
macsec policy MACSEC-P
  cipher-suite GCM-AES-XPN-256
  key-server-priority 0
  sak-expiry-time 60
  include-icv-indicator
cfs eth distribute
""",
    "Junos": """\
## Last commit: 2024-01-01 00:00:00 UTC by admin
version 21.4R3.15;
system {
    host-name MX-1;
    root-authentication {
        encrypted-password <REDACTED BY DISCONET>;
        ssh-rsa <REDACTED BY DISCONET>;
    }
    login {
        user admin {
            uid 2000;
            class super-user;
            authentication {
                encrypted-password <REDACTED BY DISCONET>;
            }
        }
        user oper {
            uid 2001;
            class read-only;
            authentication {
                ssh-rsa <REDACTED BY DISCONET>;
            }
        }
        message "Authorized access only. Key personnel. Secret.";
    }
    authentication-order [ password radius ];
    radius-server {
        10.0.0.6 {
            secret <REDACTED BY DISCONET>;
            source-address 10.10.10.3;
        }
    }
    tacplus-server {
        10.0.0.5 secret <REDACTED BY DISCONET>;
    }
    services {
        ssh {
            root-login deny;
            protocol-version v2;
            ciphers [ aes256-ctr aes256-gcm@openssh.com ];
            macs [ hmac-sha2-256 hmac-sha2-512 ];
            key-exchange [ ecdh-sha2-nistp256 ];
        }
        netconf {
            ssh;
        }
    }
    ntp {
        authentication-key 1 type md5 value <REDACTED BY DISCONET>;
        server 192.0.2.1 key 1 prefer;
        server 192.0.2.2 routing-instance MGMT;
        peer 192.0.2.3 key 1;
        trusted-key 1;
        source-address 10.255.0.1;
    }
    archival {
        configuration {
            transfer-on-commit;
            archive-sites {
                "scp://<REDACTED BY DISCONET>@10.0.0.1/backups" password <REDACTED BY DISCONET>;
                "ftp://10.0.0.1:21/backups@site";
            }
        }
    }
}
security {
    authentication-key-chains {
        key-chain ISIS-KC {
            key 1 {
                secret <REDACTED BY DISCONET>;
                start-time "2020-1-1.00:00:00 +0000";
                algorithm hmac-sha-1;
            }
        }
    }
    ike {
        proposal P1 {
            authentication-method pre-shared-keys;
            dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc;
        }
        policy IKE-POL {
            mode main;
            proposals P1;
            pre-shared-key ascii-text <REDACTED BY DISCONET>;
        }
    }
}
interfaces {
    ge-0/0/0 {
        description "Uplink to CORE - key account";
        unit 0 {
            family inet {
                address 10.1.1.1/30;
            }
            family iso;
            family mpls;
        }
    }
    ge-0/0/1 {
        description "jump host passwd <REDACTED BY DISCONET>
        unit 0 {
            family inet;
        }
    }
    lo0 {
        description "Key Account loopback";
        unit 0 {
            family inet {
                address 10.255.0.1/32;
            }
        }
    }
    fxp0 {
        description "OOB key";
        unit 0 {
            family inet {
                address 10.10.10.3/24;
            }
        }
    }
    irb {
        unit 100 {
            description "Servers key account";
            family inet {
                address 10.10.10.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.10.10.4;
                        authentication-type md5;
                        authentication-key <REDACTED BY DISCONET>;
                    }
                }
            }
        }
    }
}
snmp { ## Warning: 'snmp' is deprecated
    location "Belgrade DC1 rack 12";
    contact "noc@example.com";
    community <REDACTED BY DISCONET> {
        authorization read-only;
        clients {
            192.0.2.0/24;
        }
    }
    community <REDACTED BY DISCONET> {
        authorization read-write;
    }
    trap-group <REDACTED BY DISCONET> {
        version v2;
        targets {
            192.0.2.9;
        }
    }
    v3 {
        usm {
            local-engine {
                user snmpuser {
                    authentication-sha {
                        authentication-key <REDACTED BY DISCONET>;
                    }
                    privacy-aes128 {
                        privacy-key <REDACTED BY DISCONET>;
                    }
                }
            }
        }
    }
}
policy-options {
    policy-statement EXPORT-VRF-A {
        term 1 {
            then {
                community add VRF-A-RT;
                accept;
            }
        }
    }
    policy-statement IMPORT-VRF-A {
        term 1 {
            from community VRF-A-RT;
            then accept;
        }
    }
    community VRF-A-RT members target:65000:100;
    community SNMP-MGMT-RT members target:65000:999;
}
protocols {
    bgp {
        group IBGP {
            type internal;
            local-address 10.255.0.1;
            authentication-key <REDACTED BY DISCONET>;
            authentication-key-chain BGP-KC;
            family inet-vpn {
                unicast;
            }
            neighbor 10.255.0.2 {
                description "iBGP to PE2 key account";
            }
        }
    }
    isis {
        level 2 {
            authentication-key <REDACTED BY DISCONET>;
            authentication-type md5;
            authentication-key-chain ISIS-KC;
        }
        interface ge-0/0/0.0 {
            point-to-point;
            level 2 hello-authentication-key-chain ISIS-KC;
        }
        interface lo0.0 {
            passive;
        }
    }
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                authentication {
                    md5 1 key <REDACTED BY DISCONET>;
                }
            }
        }
    }
    ldp {
        interface ge-0/0/0.0;
        session 10.255.0.2 {
            authentication-key <REDACTED BY DISCONET>;
        }
    }
    rsvp {
        interface ge-0/0/0.0 {
            authentication-key <REDACTED BY DISCONET>;
        }
    }
    lldp {
        interface all;
    }
}
routing-instances {
    VRF-A {
        instance-type vrf;
        interface irb.100;
        route-distinguisher 65000:100;
        vrf-target target:65000:100;
        vrf-table-label;
    }
    MGMT {
        instance-type virtual-router;
        interface fxp0.0;
    }
}
""",
    "ASA": """\
: Saved
ASA Version 9.16(4)
!
hostname ASA-1
domain-name example.com
enable password <REDACTED BY DISCONET>
passwd <REDACTED BY DISCONET>
names
no mac-address auto
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.1 255.255.255.0
!
interface GigabitEthernet0/1
 description Inside - key account LAN
 nameif inside
 security-level 100
 ip address 10.10.10.254 255.255.255.0
!
interface Management0/0
 management-only
 nameif management
 security-level 100
 ip address 10.10.20.1 255.255.255.0
!
banner motd (c) Example Corp. Authorized access only.
banner motd !!! WARNING: key personnel only !!!
banner exec Welcome
banner login Secret <REDACTED BY DISCONET>
ftp mode passive
object network INSIDE-NET
 subnet 10.10.10.0 255.255.255.0
 description Key Account LAN
object-group network KEY-SERVERS
 description key servers
 network-object host 10.10.10.5
access-list OUTSIDE_IN extended permit tcp any host 203.0.113.5 eq https
nat (inside,outside) source dynamic INSIDE-NET interface
access-group OUTSIDE_IN in interface outside
route outside 0.0.0.0 0.0.0.0 203.0.113.254 1
aaa-server TACGRP protocol tacacs+
aaa-server TACGRP (inside) host 10.0.0.5
 key <REDACTED BY DISCONET>
 timeout 5
aaa-server RADGRP protocol radius
aaa-server RADGRP (inside) host 10.0.0.6
 key <REDACTED BY DISCONET>
 radius-common-pw <REDACTED BY DISCONET>
 authentication-port 1812
aaa authentication ssh console TACGRP LOCAL
aaa authentication enable console TACGRP LOCAL
user-identity default-domain LOCAL
http server enable
http 10.10.20.0 255.255.255.0 management
snmp-server host inside 192.0.2.9 community <REDACTED BY DISCONET> version 2c
snmp-server host inside 192.0.2.9 poll community <REDACTED BY DISCONET> version 2c udp-port 161
snmp-server host inside 192.0.2.10 trap community 0 <REDACTED BY DISCONET> version 2c
snmp-server host management 192.0.2.11 version 3 <REDACTED BY DISCONET>
snmp-server host management 2001:db8::9 community <REDACTED BY DISCONET>
snmp-server host inside 192.0.2.12 poll
snmp-server host inside 192.0.2.13
snmp-server host-group inside NMS-GRP community <REDACTED BY DISCONET>
snmp-server user snmpuser SNMP-GRP v3 engineID 8000000 encrypted auth sha <REDACTED BY DISCONET>
snmp-server group SNMP-GRP v3 priv
snmp-server location Belgrade DC1 rack 12
snmp-server contact noc@example.com
snmp-server community <REDACTED BY DISCONET>
snmp-server enable traps snmp authentication linkup linkdown coldstart
crypto ipsec ikev1 transform-set TS esp-aes-256 esp-sha-hmac
crypto ipsec ikev2 ipsec-proposal AES256
 protocol esp encryption aes-256
 protocol esp integrity sha-1
crypto map CMAP 10 match address VPN-ACL
crypto map CMAP 10 set peer 192.0.2.1
crypto map CMAP 10 set ikev1 transform-set TS
crypto map CMAP interface outside
crypto ca trustpoint CA
 enrollment url http://ca.example.com:80/certsrv/mscep/mscep.dll
 keypair KEY
 crl configure
crypto ikev1 enable outside
crypto ikev1 policy 10
 authentication pre-share
 encryption aes-256
 hash sha
 group 14
 lifetime 86400
crypto ikev1 policy 20
 authentication rsa-sig
 encryption aes
 hash sha
 group 5
crypto ikev1 policy 30
 authentication crack
 encryption aes
 hash sha
 group 5
crypto ikev2 policy 1
 encryption aes-256
 integrity sha256
 group 14
 prf sha256
 lifetime seconds 86400
crypto ikev2 enable outside
telnet timeout 5
ssh stricthostkeycheck
ssh 10.10.20.0 255.255.255.0 management
ssh timeout 30
ssh version 2
ssh key-exchange group dh-group14-sha256
ssh cipher encryption high
console timeout 0
ntp authentication-key <REDACTED BY DISCONET>
ntp authenticate
ntp trusted-key 1
ntp server 192.0.2.1 key 1 source inside prefer
ntp server 192.0.2.2 source inside
dhcpd address 10.10.10.100-10.10.10.200 inside
threat-detection basic-threat
tunnel-group 192.0.2.1 type ipsec-l2l
tunnel-group 192.0.2.1 ipsec-attributes
 ikev1 pre-shared-key <REDACTED BY DISCONET>
 ikev2 remote-authentication pre-shared-key <REDACTED BY DISCONET>
 ikev2 local-authentication pre-shared-key <REDACTED BY DISCONET>
tunnel-group RA type remote-access
tunnel-group RA general-attributes
 address-pool VPN-POOL
 authentication-server-group RADGRP
tunnel-group RA webvpn-attributes
 group-alias RA enable
username admin password <REDACTED BY DISCONET>
username admin attributes
 service-type admin
username vpnuser password <REDACTED BY DISCONET>
failover
failover lan unit primary
failover lan interface FO GigabitEthernet0/3
failover key <REDACTED BY DISCONET>
failover ipsec pre-shared-key <REDACTED BY DISCONET>
failover link FO GigabitEthernet0/3
failover interface ip FO 203.0.113.249 255.255.255.252 standby 203.0.113.250
logging host inside 10.10.10.50
webvpn
 enable outside
 anyconnect image disk0:/anyconnect.pkg 1
 anyconnect enable
group-policy GP internal
group-policy GP attributes
 vpn-tunnel-protocol ikev2 ssl-client
 webvpn
  anyconnect keep-installer installed
Cryptochecksum:0123456789abcdef0123456789abcdef
: end
""",
    "OPERATIONAL": """\
Interface                      Status         Protocol Description
Gi1                            up             up       Uplink to CORE key account
Gi2                            admin down     down     secret <REDACTED BY DISCONET>
Lo0                            up             up       Key Account loopback
Vl10                           up             up       Servers key account
Tu0                            up             up       DMVPN key tunnel
Po1                            up             up       vPC peer-link key account
Te1/0/1                        up             up       key access
Twe1/0/1                       up             up       key access 25G
Fo1/0/1                        up             up       key access 40G
Hu1/0/1                        up             up       key access 100G
Ap1/0/1                        up             up       key app
Bl1/0/1                        up             up       key bluetooth
BD10                           up             up       key bdi
Nu0                            up             up       key null
Interface          Status      Protocol    Description
--------------------------------------------------------------------------------
Lo0                up          up          Key Account loopback
Mg0/RP0/CPU0/0     up          up          OOB key mgmt
Gi0/0/0/0          up          up          Key Account uplink
BE1                up          up          Key Account bundle
tt1                up          up          key te tunnel
Nu0                up          up          key null
-------------------------------------------------------------------------------
Interface                Description
-------------------------------------------------------------------------------
mgmt0                    OOB key mgmt
Vlan10                   Servers key account
-------------------------------------------------------------------------------
Port          Type   Speed   Description
-------------------------------------------------------------------------------
Eth1/1        eth    10G     Uplink to CORE key account
Eth1/2        eth    1000    to firewall secret
Po1           eth    10G     vPC peer-link key
nve1          eth    --      VXLAN key
Lo0           eth    --      Key Account loopback
Interface       Admin Link Description
ge-0/0/0        up    up   Uplink to CORE - key account
ge-0/0/0.0      up    up   Uplink unit key
lo0             up    up   Key Account loopback
fxp0            up    up   OOB key
irb.100         up    up   Servers key account
ae0             up    up   LAG key
et-0/0/0        up    up   100G key
xe-0/0/1        up    up   10G key
em0             up    up   mgmt key
RP/0/RP0/CPU0:PE-XR#show interfaces description
Interface          Status      Protocol    Description
--------------------------------------------------------------------------------
MgmtEth0/RP0/CPU0/0 up         up          OOB key mgmt
Gi0/0/0/1          up          up          Key Account core
PT0/RP0/CPU0/0     admin-down  admin-down  key timing port
Gi0/0/0/2          up          up          Key Account access
pw-ether1          up          up          Key Account pseudowire headend
SR-TE1             up          up          Key Account policy
ti0/0/0/0          up          up          key tunnel-ip
BE2                up          up          Key Account bundle
Gi0/0/0/3          up          up          lab link password <REDACTED BY DISCONET>
RP/0/RP0/CPU0:PE-XR#show running-config router bgp
router bgp 65000
 neighbor 10.255.0.2
  password <REDACTED BY DISCONET>
R1#show running-config | include key
 key <REDACTED BY DISCONET>
R1#show ip arp
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.1.1.2                0   0011.2233.4455  ARPA   GigabitEthernet1
R1#show cdp neighbors detail
Device ID: SW1.example.com
Entry address(es):
  IP address: 10.0.0.5
Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP
Interface: GigabitEthernet1,  Port ID (outgoing port): GigabitEthernet1/0/1
Version :
Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4, RELEASE SOFTWARE (fc5)
Management address(es):
  IP address: 10.0.0.5
R1#show version
Cisco IOS XE Software, Version 17.09.04a
System image file is "bootflash:packages.conf"
License Level: network-advantage
Technology Package License Information:
Processor board ID 9ABCDEFGHIJ
cisco C8300-1N1S-4T2X (1RU) processor with 3763327K/6147K bytes of memory.
Configuration register is 0x2102
RP/0/RP0/CPU0:PE-XR#show lldp neighbors detail
Local Interface: GigabitEthernet0/0/0/0
Chassis id: 0011.2233.4455
Port id: Gi1/0/1
Port Description: key access
System Name: SW1
System Description: Cisco IOS Software, Key Account build
System Capabilities: B,R
Enabled Capabilities: B
Management Addresses:
  IPv4 address: 10.0.0.5
N9K-1# show bgp sessions
Neighbor        ASN    Flaps LastUpDn|LastRead|LastWrit St Port(L/R)  Notif(S/R)
10.255.0.2      65000  0     1w2d    |never   |never    E  179/42312   0/0
Password: *****
Password:
password <REDACTED BY DISCONET>
Login incorrect: bad password
admin@MX-1> show configuration snmp | display set
set snmp location "Belgrade DC1 rack 12"
set snmp community <REDACTED BY DISCONET>
set snmp community <REDACTED BY DISCONET>
set snmp community <REDACTED BY DISCONET>
set snmp trap-group <REDACTED BY DISCONET>
set policy-options community VRF-A-RT members target:65000:100
admin@MX-1> show configuration snmp
snmp { /* NOC */
    community <REDACTED BY DISCONET>;
}
community VRF-A-RT members target:65000:100;
R1#show running-config | include snmp
snmp-server community <REDACTED BY DISCONET>
snmp-server community <REDACTED BY DISCONET>
snmp-server host 192.0.2.9 version 2c <REDACTED BY DISCONET>
""",
}

# The lines whose pinned result the code does not give yet, by the finding
# that fixes them: (fragment, source line), every occurrence of that line in
# that fragment.
# Empty: every line of the battery redacts to its pin. A line found wrong is
# listed here under the finding that fixes it, or under `open:`, with an
# expected failure of its own in `TheLinesNotRightYet`.
KNOWN: dict[str, set[tuple[str, str]]] = {}

# What the fragments use for secrets, and the lines whose pinned result may
# still show one: they are not secrets where they stand.
SECRETS = (
    "Pa55w0rd", "S3CRET", "c0mmun1ty", "k3y", "p@ss", "Welcome123", "c0ff:ee", "1234:5678",
    "10.20.30.40", "1234/x", "$9$", "$6$", "$5$", "$sha512$",
)
NOT_SECRETS = {
    ("IOS-XE", " description Key Account loopback for S3CRET-customer"),
}


def _lines(name: str) -> list[tuple[int, str, str, str]]:
    """(number, source, redacted, pinned) of every line of one fragment."""
    source = FRAGMENTS[name].splitlines()
    redacted = redact(FRAGMENTS[name])[0].splitlines()
    pinned = EXPECTED[name].splitlines()
    return [(n, s, r, p) for n, (s, r, p) in enumerate(zip(source, redacted, pinned), 1)]


class EveryLineOfTheBatteryIsRedactedAsPinned(unittest.TestCase):
    def test_every_line_not_known_to_be_wrong_redacts_to_its_pinned_result(self):
        known = set().union(*KNOWN.values())
        for name in FRAGMENTS:
            for number, source, redacted, pinned in _lines(name):
                if (name, source) in known:
                    continue
                with self.subTest(fragment=name, line=number, source=source):
                    self.assertEqual(redacted, pinned)

    def test_the_pinned_results_line_up_with_their_fragments(self):
        self.assertEqual(list(EXPECTED), list(FRAGMENTS))
        for name in FRAGMENTS:
            with self.subTest(fragment=name):
                self.assertEqual(len(EXPECTED[name].splitlines()), len(FRAGMENTS[name].splitlines()))
                self.assertEqual(len(redact(FRAGMENTS[name])[0].splitlines()), len(FRAGMENTS[name].splitlines()))

    def test_the_count_is_the_number_of_lines_that_changed(self):
        for name in FRAGMENTS:
            with self.subTest(fragment=name):
                _, changed = redact(FRAGMENTS[name])
                self.assertEqual(changed, sum(source != redacted for _, source, redacted, _ in _lines(name)))

    def test_no_pinned_result_shows_a_secret(self):
        """A guard on the pins themselves: an edit that kept a secret would be held as right."""
        for name in FRAGMENTS:
            for number, source, _, pinned in _lines(name):
                if (name, source) in NOT_SECRETS:
                    continue
                with self.subTest(fragment=name, line=number, source=source):
                    self.assertEqual([s for s in SECRETS if s in pinned], [])

    def test_every_known_line_is_in_its_fragment(self):
        for group, lines in KNOWN.items():
            for name, source in lines:
                with self.subTest(group=group, source=source):
                    self.assertIn(source, FRAGMENTS[name].splitlines())


class TheLinesNotRightYet(unittest.TestCase):
    """One test per group in KNOWN, expected to fail until the group's fix lands."""

    def assert_group(self, group: str) -> None:
        wrong = [
            (name, source, redacted, pinned)
            for name in FRAGMENTS
            for _, source, redacted, pinned in _lines(name)
            if (name, source) in KNOWN[group] and redacted != pinned
        ]
        self.assertEqual(wrong, [])

    def test_every_group_has_its_test(self):
        tests = [getattr(self, name) for name in dir(self) if name.startswith("test_") and name != "test_every_group_has_its_test"]
        self.assertEqual(len(tests), len(KNOWN))


class AKeywordInsideABgpNameIsNoSecret(unittest.TestCase):
    """A peer-group, template or group named `IBGP-MD5` or `RR-KEY` is a name.

    The keyword rule took the `md5` or `key` at its end for the keyword and
    the rest of the line for its value, so `neighbor IBGP-MD5
    route-reflector-client` was stored as `neighbor IBGP-MD5 <REDACTED>`
    and the route reflector it named was lost with it. What follows the name
    is still read: a password given to that peer-group is redacted.
    """

    def redacted(self, line: str) -> str:
        return redact(line)[0]

    def test_what_follows_a_name_ending_in_a_keyword_is_kept(self):
        for line in (
            " neighbor IBGP-MD5 route-reflector-client",
            " neighbor RR-KEY route-reflector-client",
            " neighbor IBGP-MD5 remote-as 65000",
            " neighbor 10.0.0.11 peer-group IBGP-MD5",
            " neighbor 10.0.0.11 inherit peer-policy RR-KEY 10",
            " neighbor-group RR-SECRET",
            "  use neighbor-group RR-SECRET",
            " template peer-policy RR-KEY",
            "  inherit peer-policy CLIENT-MD5 10",
        ):
            with self.subTest(line=line):
                self.assertEqual(self.redacted(line), line)

    def test_a_secret_given_to_such_a_name_is_still_redacted(self):
        for line, kept in (
            (" neighbor IBGP-MD5 password 7 0822455D0A16", " neighbor IBGP-MD5 password"),
            (" neighbor RR-KEY password S3cret", " neighbor RR-KEY password"),
            ("  password encrypted 0822455D0A16", "  password"),
        ):
            with self.subTest(line=line):
                self.assertEqual(self.redacted(line), f"{kept} {REDACTION_MARKER}")

    def test_a_compound_keyword_is_still_a_keyword(self):
        for line, kept in (
            ("  pre-shared-key local S3CRET", "  pre-shared-key"),
            # `accept`: R4 keeps the mode words of `lsp-password hmac-md5 encrypted X level 2`, and no other shape's.
            ("  lsp-password accept encrypted 0123Pa55w0rd level 2", "  lsp-password"),
            (" area-password S3CRET", " area-password"),
            (" domain-password S3CRET", " domain-password"),
        ):
            with self.subTest(line=line):
                self.assertEqual(self.redacted(line), f"{kept} {REDACTION_MARKER}")


class ABfdTemplateNamesItsKeyChain(unittest.TestCase):
    """F-35's narrowing lost the BFD template's chain: `authentication sha-1 keychain KC`.

    The chain is named after the hash on IOS-XE and NX-OS, the meticulous
    forms included; the key is in the chain, not on this line.
    """

    def test_the_chain_after_a_bfd_hash_is_kept(self):
        for line in (
            "  authentication sha-1 keychain BFD-KC",
            "  authentication md5 keychain BFD-KC",
            "  authentication meticulous-sha-1 keychain BFD-KC",
            "  authentication meticulous-md5 keychain BFD-KC",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line)[0], line)

    def test_a_password_named_keychain_is_still_a_password(self):
        self.assertEqual(redact("username bob password keychain")[0], f"username bob password {REDACTION_MARKER}")


class ACredentialInADescriptionByItsShortWords(unittest.TestCase):
    """D3 redacts a description's tail after a credential word; `pwd` and `psk` are such words too.

    `pass` is one only where it is given a value (`pass: X`, `pass=X`): as a
    word on its own it is a pass-through or a bypass. `pw` stays out: a
    pseudowire's description says `PW to PE2`.
    """

    def test_the_short_words_lose_what_follows(self):
        for line, kept in (
            (" description pwd: Welcome123", " description pwd"),
            (" description psk=Welcome123", " description psk"),
            (" description guest wifi pass: Welcome123", " description guest wifi pass"),
            (" description pass=Welcome123", " description pass"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line)[0], f"{kept} {REDACTION_MARKER}")

    def test_words_that_only_look_like_them_are_kept(self):
        for line in (
            " description PW to PE2 for customer A",
            " description pass-through to the firewall",
            " description bypass link to DC2",
            " description pass through to the core",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line)[0], line)


class AKeyNumberIsNoSecret(unittest.TestCase):
    """`ntp trusted-key 1` and a Junos chain's `key 1 {` number a key; the secret is elsewhere.

    The key they number is still redacted where it is written, and a number
    after `key` is still the secret where nothing says it numbers one.
    """

    def test_a_trusted_key_or_a_junos_chain_key_keeps_its_number(self):
        for config in (
            "ntp trusted-key 1",
            "ntp trusted-key 1 - 3",
            "ntp\n trusted-key 1",
            "system {\n    ntp {\n        trusted-key 1;",
            "system {\n    ntp {\n        trusted-key [ 1 2 ];",
            "security {\n    authentication-key-chains {\n        key-chain ISIS-KC {\n            key 1 {",
        ):
            with self.subTest(config=config):
                self.assertEqual(redact(config), (config, 0))

    def test_the_key_they_number_is_still_redacted(self):
        for config, secret in (
            ("ntp authentication-key 1 md5 Pa55w0rd 7\nntp trusted-key 1", "Pa55w0rd"),
            ("ntp\n authentication-key 1 md5 encrypted 0123Pa55w0rd\n trusted-key 1", "Pa55w0rd"),
            ('system {\n    ntp {\n        authentication-key 1 type md5 value "$9$Pa55w0rd"; ## SECRET-DATA\n'
             "        trusted-key 1;", "$9$"),
            ("security {\n    authentication-key-chains {\n        key-chain ISIS-KC {\n            key 1 {\n"
             '                secret "$9$Pa55w0rd"; ## SECRET-DATA', "$9$"),
        ):
            with self.subTest(config=config):
                out, changed = redact(config)
                self.assertNotIn(secret, out)
                self.assertEqual(changed, 1)

    def test_a_number_after_key_elsewhere_is_still_the_secret(self):
        for config, secret in (
            ("trusted-key 4711", "4711"),
            ("ntp trusted-key 4711 S3CRET", "S3CRET"),
            ("tacacs server TAC1\n key 4711", "4711"),
            ("security {\n    authentication-key-chains {\n        key 4711 {", "4711"),
        ):
            with self.subTest(config=config):
                self.assertNotIn(secret, redact(config)[0])


class AModeAfterAKeywordIsNoSecret(unittest.TestCase):
    """`mode md5 level-2`, `password required` and `authentication-order [ password radius ]` carry no secret.

    Each says how a peer or a login is authenticated, not with what. One
    word more than the mode takes, and the line is read as any other.
    """

    def test_a_mode_keeps_every_word(self):
        for line in (
            " isis authentication mode md5 level-2",
            " isis authentication mode text level-1",
            " authentication mode md5 level-2",
            "mpls ldp password required",
            "mpls ldp password required for LDP-PEERS",
            "    authentication-order [ password radius ];",
            "    authentication-order [ radius tacplus password ];",
            "    authentication-order password;",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_secret_beside_a_mode_still_goes(self):
        for line, kept in (
            (" isis authentication mode md5 S3CRET", " isis authentication mode md5"),
            (" isis authentication mode md5 level-2 S3CRET", " isis authentication mode md5"),
            ("mpls ldp password required Pa55w0rd", "mpls ldp password"),
            ("mpls ldp password fallback 7 Pa55w0rd", "mpls ldp password"),
            ("mpls ldp password option 1 for ACL1 Pa55w0rd", "mpls ldp password"),
            ("mpls ldp neighbor 10.255.0.2 password required", "mpls ldp neighbor 10.255.0.2 password"),
            ("    authentication-order [ password S3CRET ];", "    authentication-order [ password"),
            (" isis password S3CRET level-2", " isis password"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))


class ABannerIsReadAsADescriptionIs(unittest.TestCase):
    """A banner is free text: what follows a credential word goes, and nothing after `key` (D3).

    The text of an IOS, IOS-XR or NX-OS banner runs over the lines up to its
    closing delimiter; an ASA writes each line of it as a `banner` line of
    its own; Junos says it in `system login { message "..." }`.
    """

    def test_a_banner_keeps_every_word_but_what_follows_a_credential_word(self):
        for config, expected in (
            ("banner motd ^C\nKey personnel only.\nNo password sharing.\n^C",
             f"banner motd ^C\nKey personnel only.\nNo password {REDACTION_MARKER}\n^C"),
            ("banner motd #\nKey personnel only. Secret.\n#", "banner motd #\nKey personnel only. Secret.\n#"),
            ("banner login ^CKey personnel only^C", "banner login ^CKey personnel only^C"),
            ("banner exec key holders only", "banner exec key holders only"),
            ("banner motd !!! WARNING: key personnel only !!!", "banner motd !!! WARNING: key personnel only !!!"),
            ("banner login community Welcome123", f"banner login community {REDACTION_MARKER}"),
            ('system {\n    login {\n        message "Key personnel. Password: Welcome123";',
             f'system {{\n    login {{\n        message "Key personnel. Password {REDACTION_MARKER}'),
            ('system {\n    login {\n        announcement "Key rotation tonight";',
             'system {\n    login {\n        announcement "Key rotation tonight";'),
        ):
            with self.subTest(config=config):
                self.assertEqual(redact(config)[0], expected)

    def test_the_configuration_after_a_banner_is_read_as_configuration(self):
        out, changed = redact(
            "banner motd ^C\nKey personnel only.\n^C\nkey chain KC\n key 1\n  key-string 7 Pa55w0rd\n"
            "banner motd #\nKey personnel only.\n#\nsnmp-server community c0mmun1ty RO\n"
        )
        self.assertNotIn("Pa55w0rd", out)
        self.assertNotIn("c0mmun1ty", out)
        self.assertIn("Key personnel only.", out)
        self.assertEqual(changed, 2)

    def test_a_banner_that_never_closes_takes_no_configuration_with_it(self):
        """A configuration cut short, or a delimiter that is text: each line after it is read as configuration."""
        for config in (
            "banner motd ^C\nKey personnel only.\n key-string 7 Pa55w0rd\n tacacs-server key k3y",
            # An ASA banner line opening with punctuation is closed on itself:
            # a later line ending in the same character does not make the
            # lines between them banner text.
            "banner motd (c) Example Corp.\n key-string 7 Pa55w0rd\n tacacs-server key k3y\nobject network X (",
            "banner motd - Authorized only\n key-string 7 Pa55w0rd\n tacacs-server key k3y\n description -",
        ):
            with self.subTest(config=config):
                out = redact(config)[0]
                self.assertNotIn("Pa55w0rd", out)
                self.assertNotIn("k3y", out)

    def test_a_message_outside_a_junos_login_is_read_as_configuration(self):
        self.assertNotIn("k3y", redact('system {\n    services {\n        message "key k3y";')[0])


class AJunosSecretDataLineKeepsItsUrlWhole(unittest.TestCase):
    """The URL pass wrote its marker first, and the secret-data rule then cut the line inside it.

    `"scp://<REDACTED <REDACTED BY DISCONET>` lost the host and split the
    marker. The URL's credentials and the password go; the host stays, and
    since G25 so does the `password` keyword before the quoted `$9$` value.
    """

    def test_the_url_keeps_its_host_and_loses_its_credentials(self):
        for line, kept in (
            ('    "scp://admin:p@ss/w0rd@10.0.0.1/backups" password "$9$Pa55w0rd"; ## SECRET-DATA',
             f'    "scp://{REDACTION_MARKER}@10.0.0.1/backups"'),
            ('    "scp://admin:Pa55w0rd@10.0.0.1/backups" password "$9$Pa55w0rd"; ## SECRET-DATA',
             f'    "scp://{REDACTION_MARKER}@10.0.0.1/backups"'),
            ('    "scp://backup@10.0.0.1/backups" password "$9$Pa55w0rd"; ## SECRET-DATA',
             '    "scp://backup@10.0.0.1/backups"'),
            ('    "scp://10.0.0.1/backups" password "$9$Pa55w0rd"; ## SECRET-DATA', '    "scp://10.0.0.1/backups"'),
        ):
            with self.subTest(line=line):
                out, changed = redact(line)
                self.assertEqual(out, f"{kept} password {REDACTION_MARKER}")
                self.assertEqual(changed, 1)

    def test_the_first_word_rule_still_keeps_the_url_whole(self):
        """G25 rule 4: with no quoted `$n$` value the line is cut at its first word, and that word is the URL."""
        for line, kept in (
            ('    "scp://admin:Pa55w0rd@10.0.0.1/backups" password Pa55w0rd; ## SECRET-DATA',
             f'    "scp://{REDACTION_MARKER}@10.0.0.1/backups"'),
            ('    "scp://admin:Pa55w0rd@10.0.0.1/backups" password "Pa55w0rd"; ## SECRET-DATA',
             f'    "scp://{REDACTION_MARKER}@10.0.0.1/backups"'),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))

    def test_the_marker_is_never_cut(self):
        out, _ = redact('    "ftp://a:b@10.0.0.1/x" "ftp://c:d@10.0.0.2/y" password "$9$Pa55w0rd"; ## SECRET-DATA')
        self.assertEqual(out.count("<REDACTED"), out.count(REDACTION_MARKER))
        self.assertNotIn("$9$", out)


class AnAsaBannerLineOfOneCharacterOpensNoBanner(unittest.TestCase):
    """C-01, a regression of the banner rule: an ASA's `banner motd *` swallowed the configuration under it.

    An ASA writes one `banner motd <text>` line per line of text, and a line
    of one punctuation character looked like the opening of an IOS or NX-OS
    banner. Its "text" ran to the next line ending in that character (an ACL
    remark of asterisks), and banner text is free text, so the TACACS,
    failover, NTP, IKE and OSPF keys between them were written in clear.
    """

    ASA = (
        "ASA Version 9.16(4)\n"
        "hostname FW1\n"
        "enable password S0enable encrypted\n"
        "interface GigabitEthernet0/0\n"
        " nameif outside\n"
        "banner motd *\n"
        "banner motd * Authorized access only *\n"
        "banner motd *\n"
        "aaa-server TAC (inside) host 192.0.2.5\n"
        " key S1tacacsKey\n"
        "failover key S2failoverKey\n"
        "ntp authentication-key 1 md5 S3ntpKey\n"
        "tunnel-group 198.51.100.1 ipsec-attributes\n"
        " ikev1 pre-shared-key S4psk\n"
        " ikev2 remote-authentication pre-shared-key S5psk\n"
        "interface GigabitEthernet0/1\n"
        " ospf message-digest-key 1 md5 S6ospf\n"
        "access-list OUTSIDE_IN remark ***** web servers *****\n"
    )
    SECRETS = ("S0enable", "S1tacacsKey", "S2failoverKey", "S3ntpKey", "S4psk", "S5psk", "S6ospf")

    def test_the_configuration_after_it_is_redacted(self):
        out = redact(self.ASA)[0]
        for secret in self.SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, out)
        self.assertIn("banner motd * Authorized access only *", out)

    def test_an_ftd_configuration_is_an_asa_s(self):
        """Firepower Threat Defense heads its configuration `NGFW Version`, and carried no ASA mark."""
        out = redact(
            ": Saved\n:\nNGFW Version 7.0.1\nhostname FW\nbanner motd *\n"
            "failover key S2failoverKey\naaa-server T (inside) host 192.0.2.5\n key S1tacacsKey\n*\n"
        )[0]
        self.assertNotIn("S2failoverKey", out)
        self.assertNotIn("S1tacacsKey", out)

    def test_without_the_asa_markers_another_banner_line_still_ends_no_body(self):
        # A transcript may hold the banner lines without `ASA Version` or a
        # `nameif`: a banner's text never holds the next `banner` line.
        text = "\n".join(line for line in self.ASA.splitlines()
                         if not line.startswith("ASA Version") and "nameif" not in line)
        out = redact(text)[0]
        for secret in self.SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, out)

    def test_the_stanzas_after_it_are_stanzas(self):
        from netstate.collector import config_stanzas

        heads = [stanza[0] for stanza in config_stanzas(self.ASA)]
        self.assertIn("aaa-server TAC (inside) host 192.0.2.5", heads)
        self.assertIn("interface GigabitEthernet0/1", heads)

    def test_an_ios_and_an_nxos_banner_still_run_over_their_lines(self):
        from netstate.collector import config_stanzas

        ios = "banner motd ^C\nKey Account NOC\nsupport password Welcome1\n^C\nenable secret 9 $9$SECRET\n"
        out = redact(ios)[0]
        self.assertIn("Key Account NOC", out)
        self.assertNotIn("Welcome1", out)
        self.assertNotIn("$9$SECRET", out)
        nxos = "banner motd #\nKey Account NOC\n#\nusername admin password 5 $5$SECRET role network-admin\n"
        self.assertIn("Key Account NOC", redact(nxos)[0])
        self.assertEqual(len(config_stanzas(nxos)[0]), 3)


class ABannerClosedAtTheEndOfItsLastLine(unittest.TestCase):
    """R-5, a regression of C-01: a typed delimiter closed a banner only on a line of its own.

    IOS-XR and NX-OS print the closing delimiter at the end of the last line
    of text as often as on a line of its own (`Key personnel only#`). That
    banner was never closed, so its text was read as configuration, and
    `Key personnel only` lost all but its first word.
    """

    BANNER = "hostname P1\nbanner motd #\nAuthorized only.\nKey personnel only#\n"
    CONFIG = "interface Gi0/0/0/0\n ipv4 address 10.0.0.1 255.255.255.0\nusername ops\n password 7 S1xr\n"

    def test_the_text_is_kept_and_the_configuration_after_it_redacted(self):
        out = redact(self.BANNER + self.CONFIG)[0]
        self.assertIn("\nAuthorized only.\nKey personnel only#\n", out)
        self.assertNotIn("S1xr", out)
        self.assertIn(" ipv4 address 10.0.0.1 255.255.255.0", out)

    def test_the_text_belongs_to_the_banner_stanza(self):
        from netstate.collector import config_stanzas

        stanzas = config_stanzas(self.BANNER + self.CONFIG)
        self.assertEqual([stanza[0] for stanza in stanzas], ["hostname P1", "banner motd #", "interface Gi0/0/0/0", "username ops"])
        self.assertEqual(stanzas[1], ["banner motd #", "Authorized only.", "Key personnel only#"])

    def test_a_delimiter_inside_a_line_is_no_banner_text(self):
        """The device ends a banner at its delimiter, so its text never holds one.

        A line with the character before its end (an ACL remark of asterisks,
        `rack #4 uplink#`) says the opening line opened no banner, and every
        line is read as configuration, rather than closed on.
        """
        for config in (
            "banner motd #\nAuthorized only.\n key-string 7 Pa55w0rd\n description rack #4 uplink#\n",
            "banner motd *\nfailover key Pa55w0rd\naccess-list OUTSIDE_IN remark ***** web servers *****\n",
            # Even where a line of its own follows.
            "banner motd %\nfailover key Pa55w0rd\n description 50% of the uplink\n%\n",
        ):
            with self.subTest(config=config):
                self.assertNotIn("Pa55w0rd", redact(config)[0])

    def test_a_character_configuration_lines_end_with_closes_only_on_a_line_of_its_own(self):
        """`*`, `-`, `.` or `)` ends a remark, a rule, a sentence or an object's line as often as a banner.

        Read as a close at the end of other text, `banner motd *` with no
        ASA mark to say what it is would turn the configuration down to
        ` description core *` into banner text, keys and all.
        """
        for config in (
            "banner motd *\nfailover key Pa55w0rd\ninterface Gi0/1\n description core *\n",
            "banner motd -\nfailover key Pa55w0rd\ninterface Gi0/1\n description uplink -\n",
            "banner motd .\nfailover key Pa55w0rd\nAuthorized only.\n",
            "banner motd )\nfailover key Pa55w0rd\nobject network WEB (10.0.0.1)\n",
        ):
            with self.subTest(config=config):
                self.assertNotIn("Pa55w0rd", redact(config)[0])
        # On a line of its own it still closes, as NX-OS prints it.
        self.assertIn("Key personnel only.", redact("banner motd *\nKey personnel only.\n*\n")[0])

    def test_an_asa_line_of_one_character_still_opens_no_banner(self):
        asa = "ASA Version 9.16(4)\nbanner motd #\nfailover key S2asa\nKey personnel only#\n"
        self.assertNotIn("S2asa", redact(asa)[0])


class ACredentialNoKeywordNamedIsRedacted(unittest.TestCase):
    """C-02: IOS-XE credentials whose line no keyword rule read were written in clear.

    The Umbrella registration token and a PKI token's PIN have words of their
    own; an EEM variable is named by the operator, and `\\b` does not fall
    between the `_` of `_password` and the keyword; an EEM action types a
    whole command, which the line rules read as the action's words.
    """

    def assert_gone(self, text: str, secret: str) -> str:
        out = redact(text)[0]
        self.assertNotIn(secret, out)
        return out

    def test_the_umbrella_token_and_a_pki_token_pin(self):
        out = self.assert_gone("parameter-map type umbrella global\n token S1A2B3C4D5E6F708\n local-domain LD", "S1A2B3")
        self.assertIn(" local-domain LD", out)
        self.assert_gone("crypto pki token default user-pin 0 S2pin1234", "S2pin1234")

    def test_every_eem_variable_loses_its_value_and_keeps_its_name(self):
        for name in ("_password", "_email_password", "_secret", "_key", "_tftp_pw", "_cron_entry"):
            with self.subTest(name=name):
                out = self.assert_gone(f"event manager environment {name} S3eemValue", "S3eemValue")
                self.assertEqual(out, f"event manager environment {name} {REDACTION_MARKER}")

    def test_the_command_an_eem_action_types_is_read_as_a_command(self):
        applet = (
            "event manager applet ROTATE\n"
            ' action 1.0 cli command "snmp-server community S4comm RO"\n'
            ' action 2.0 cli command "snmp-server host 192.0.2.9 version 2c S5comm"\n'
            ' action 3.0 cli command "interface Loopback0"\n'
        )
        out = redact(applet)[0]
        self.assertNotIn("S4comm", out)
        self.assertNotIn("S5comm", out)
        self.assertIn(' action 3.0 cli command "interface Loopback0"', out)

    def test_the_answer_to_a_password_prompt_an_action_waits_for(self):
        applet = (
            "event manager applet LOGIN\n"
            ' action 1.0 cli command "enable" pattern "Password:"\n'
            ' action 1.1 cli command "S6enable"\n'
            ' action 2.0 cli command "show clock"\n'
        )
        out = redact(applet)[0]
        self.assertNotIn("S6enable", out)
        self.assertIn(' action 1.0 cli command "enable" pattern "Password:"', out)
        self.assertIn(' action 2.0 cli command "show clock"', out)

    def test_the_answer_to_a_prompt_its_pattern_only_matches_part_of(self):
        """R-2: a pattern is a regular expression the prompt is matched against, and a fragment of it is enough.

        `pattern "word:"`, `"ssword"`, `"pass"` and `"[Pp]ass"` all wait for
        `Password:`, and named none of the words the rule looked for, so the
        answer was written in clear. An `enable` waits for its password
        whatever it is told to wait for.
        """
        for command, pattern in (
            ("enable", "word:"), ("enable", "ssword"), ("enable", "pass"), ("enable", "[Pp]ass"),
            ("enable", "#"), ("enable 15", "."), ("login", "word:"), ("login", "[Pp]ass"),
            ("login", "ssword"), ("login", "ASSPHRASE"), ("login", "cret:"), ("login", "Enter enable secret:"),
            ("login", "PIN"), ("login", "(P|p)assw"), ("login", "word: ?$"),
        ):
            with self.subTest(command=command, pattern=pattern):
                applet = (
                    "event manager applet LOGIN\n"
                    f' action 1.0 cli command "{command}" pattern "{pattern}"\n'
                    ' action 1.1 cli command "S9answer"\n'
                    ' action 2.0 cli command "show clock"\n'
                )
                out = redact(applet)[0]
                self.assertNotIn("S9answer", out)
                self.assertIn(f' action 1.0 cli command "{command}" pattern "{pattern}"', out)
                self.assertIn(' action 2.0 cli command "show clock"', out)

    def test_an_action_that_waits_for_no_password_prompt_keeps_its_answer(self):
        # `[confirm]` unescaped is a class of letters `Password:` has, and is read as the device reads it.
        for pattern in ("confirm", "\\[confirm\\]", "\\[startup-config\\]", "#", "yes/no", "Destination filename", "[(*"):
            with self.subTest(pattern=pattern):
                applet = (
                    "event manager applet SAVE\n"
                    f' action 1.0 cli command "copy running-config startup-config" pattern "{pattern}"\n'
                    ' action 1.1 cli command "y"\n'
                )
                self.assertIn(' action 1.1 cli command "y"', redact(applet)[0])

    def test_the_password_of_an_eem_mail_server_goes_and_its_user_and_host_stay(self):
        """R-1: Cisco documents `user:password@host` for the server an EEM `mail` action sends through.

        The value has no `://`, so the URL pass never read it, and the
        password was written in clear to the raw file and to connect.log.
        """
        for line, expected in (
            (' action 1.0 mail server "mailer:S8mail@192.0.2.22" to "noc@example.net" from "r1@example.net"'
             ' subject "link" body "down"',
             f' action 1.0 mail server "mailer:{REDACTION_MARKER}@192.0.2.22" to "noc@example.net"'
             ' from "r1@example.net" subject "link" body "down"'),
            # A password with an `@` or a `:` in it runs to the last `@`.
            (' action 1.0 mail server "mailer:S8m@il:x@smtp.example.net" to "a@example.net"',
             f' action 1.0 mail server "mailer:{REDACTION_MARKER}@smtp.example.net" to "a@example.net"'),
            (" action 1.0 mail server mailer:S8mail@192.0.2.22 to noc@example.net",
             f" action 1.0 mail server mailer:{REDACTION_MARKER}@192.0.2.22 to noc@example.net"),
        ):
            with self.subTest(line=line):
                out, changed = redact(line)
                self.assertEqual(out, expected)
                self.assertEqual(changed, 1)
        # A server named without credentials, or by a variable, keeps every word.
        for line in (' action 1.0 mail server "192.0.2.22" to "noc@example.net"',
                     ' action 1.0 mail server "$_email_server" to "$_email_to"'):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))


class TheSmallerCommunityAndUrlGaps(unittest.TestCase):
    """C-04: an SNMP community in Junos set form, under IOS-XR's `snmp-server vrf`, and a URL with no user."""

    def assert_gone(self, text: str, secret: str) -> str:
        out = redact(text)[0]
        self.assertNotIn(secret, out)
        return out

    def test_a_junos_community_in_set_form(self):
        self.assert_gone("set snmp community S1pub authorization read-only", "S1pub")
        self.assert_gone('set snmp community "S2pub rw" clients 192.0.2.0/24', "S2pub")
        # A BGP community in set form is a route target's, as in braces.
        line = "set policy-options community VRF-A-RT members target:65000:100"
        self.assertEqual(redact(line)[0], line)

    def test_a_junos_snmp_block_with_a_comment_after_its_brace(self):
        out = self.assert_gone("snmp { /* NOC */\n    community S3pub;\n}\ncommunity RT members target:65000:1;", "S3pub")
        self.assertIn("community RT members target:65000:1;", out)

    def test_an_xr_vrf_host_line_that_names_no_traps_informs_or_version(self):
        self.assert_gone("snmp-server vrf MGMT\n host 192.0.2.9 encrypted S4comm", "S4comm")
        out = self.assert_gone("snmp-server vrf MGMT\n host 192.0.2.9 clear S5comm udp-port 1162", "S5comm")
        self.assertIn(" host 192.0.2.9 ", out)
        # A Junos host stanza says none of them either, and opens a block.
        self.assertEqual(redact("snmp {\n    trap-group NOC {\n        targets {\n            192.0.2.9;")[0].splitlines()[-1],
                         "            192.0.2.9;")

    def test_a_url_with_an_empty_user_or_a_quoted_password(self):
        self.assertEqual(redact(" path ftp://:S6pass@192.0.2.8/cfg")[0], f" path ftp://{REDACTION_MARKER}@192.0.2.8/cfg")
        self.assertEqual(redact('copy scp://ops:"S7 pass"@192.0.2.8/x flash:')[0],
                         f"copy scp://{REDACTION_MARKER}@192.0.2.8/x flash:")


class AControlCharacterDefeatsNoRule(unittest.TestCase):
    """C-07: the control characters were stripped when a snapshot was read, after redaction.

    A terminal escape, a NUL or a pager's prompt in front of a line defeated
    every rule anchored at the line's start, and the reader then stripped it
    and had the community in clear.
    """

    LINES = (
        "\x1b[Ksnmp-server community S1comm RO",
        "\x00snmp-server host 192.0.2.9 version 2c S2comm",
        " --More-- " + "\b" * 10 + " " * 10 + "\b" * 10 + "snmp-server community S3comm RO",
        "<--- More --->\r              \rsnmp-server community S4comm RO",
        "---(more 42%)---\r                \r    community S5comm;",
    )

    def test_the_text_is_cleaned_before_it_is_redacted(self):
        for line in self.LINES:
            with self.subTest(line=line):
                out = redact("snmp {\n" + line if "community S5" in line else line)[0]
                self.assertNotRegex(out, r"S\dcomm")
                self.assertNotRegex(out, r"[\x00-\x08\x1b]")

    def test_an_invisible_character_pasted_in_front_of_a_line_is_removed(self):
        """A zero-width space or a byte-order mark, pasted with a configuration, hid the keyword from the rule."""
        for mark in ("\u200b", "\ufeff", "\u2060", "\u00ad", "\u200e"):
            with self.subTest(mark=repr(mark)):
                out = redact(mark + "snmp-server community S1comm RO")[0]
                self.assertNotIn("S1comm", out)
                self.assertNotIn(mark, out)

    def test_no_escape_leaves_a_byte_in_front_of_the_line(self):
        """R-4: an escape that is not ESC and one byte of 0x40-0x5F left its last byte at the line's start.

        `ESC ( B` left `(B` in front of `snmp-server community X RO`, an OSC
        title its text, a C1 CSI its parameters, and a pager prompt in reverse
        video was hidden from the prompt rule by the escapes around it; each
        line then started with something no rule anchored at its start reads.
        """
        from netstate.collector import clean_text

        erased = "\b" * 10 + " " * 10 + "\b" * 10
        for prefix in (
            "\x1b7", "\x1b8", "\x1b=", "\x1b>", "\x1b(B", "\x1b)0", "\x1b#8", "\x1bc",
            "\x1b]0;R1\x07", "\x1b]2;R1: show run\x1b\\", "\x9b0m", "\x9b?25l", "\x1b[?2004h",
            "\x1b[7m --More-- \x1b[27m" + erased, " --More--\x1b[8D\x1b[K", "\x1b[7m<--- More --->\x1b[0m" + erased,
        ):
            with self.subTest(prefix=prefix):
                self.assertEqual(clean_text(prefix + "snmp-server community S8comm RO\n"),
                                 "snmp-server community S8comm RO\n")
                self.assertEqual(redact(prefix + "snmp-server community S8comm RO")[0],
                                 f"snmp-server community {REDACTION_MARKER}")
        # A prompt erased by a carriage return leaves the return, which ends a line.
        out = redact("\x1b[7m--More--\x1b[m\r        \rsnmp-server community S8comm RO")[0]
        self.assertEqual(out.splitlines()[-1], f"snmp-server community {REDACTION_MARKER}")
        self.assertNotIn("More", out)

    def test_a_pager_prompt_erased_by_backspaces_takes_no_indentation_with_it(self):
        from netstate.collector import clean_text

        erased = " --More-- " + "\b" * 10 + " " * 10 + "\b" * 10
        self.assertEqual(clean_text(erased + " key 7 S6key\n"), " key 7 S6key\n")
        # Words that only look like a prompt, with nothing erasing them, are words.
        self.assertEqual(clean_text(" description see --More-- below"), " description see --More-- below")

    def test_the_raw_file_and_the_transcript_are_both_cleaned_first(self):
        import tempfile
        from pathlib import Path

        from netstate.collector import _write_raw, redact_transcript

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw" / "show_running_config.txt"
            parsed, changed = _write_raw(path, self.LINES[0] + "\nhostname R1")
            self.assertEqual(parsed, f"snmp-server community {REDACTION_MARKER}\nhostname R1")
            self.assertEqual(changed, 1)
            self.assertEqual(path.read_text(encoding="utf-8"), parsed + "\n")
        transcript = redact_transcript("R1#show run\n" + self.LINES[1] + "\nlogin: ops\nPassword: S7login\x1b[K\n", ["S7login"])
        self.assertNotIn("S2comm", transcript)
        self.assertNotIn("S7login", transcript)


class AKeywordInsideAPolicyNameIsNoSecret(unittest.TestCase):
    """C4-01: a route-map, list, set or policy named `EXPORT-KEY` or `RT-KEY` is a name, as a BGP group's is.

    The keyword rule took the `key` at the end of the name for the keyword
    and the rest of the line for its value, so `route-map EXPORT-KEY permit
    10` lost its sequence and Junos `community RT-KEY members target:...`
    its targets: the VRF built on them read as exporting nothing. The same
    cut kept an SNMP community ending in a keyword whole (`snmp-server
    community ops-secret RO` kept `ops-secret`), which is the secret.
    """

    def test_what_follows_a_policy_name_ending_in_a_keyword_is_kept(self):
        for line in (
            "route-map EXPORT-KEY permit 10",
            "route-map RM-MD5 deny 20",
            "ip prefix-list PL-SHA seq 5 permit 10.0.0.0/8 le 24",
            "ipv6 prefix-list PL6-TOKEN seq 5 permit 2001:db8::/32",
            "ip community-list standard CL-KEY permit 65000:10",
            "ip community-list expanded CL-MD5 permit _65000:.*_",
            "ip extcommunity-list standard RT-KEY permit rt 65000:10",
            "ip extcommunity-list RT-SHA-256 permit rt 65000:10",
            "ip as-path access-list AS-KEY permit ^65000$",
            " match ip address prefix-list PL-KEY PL-MD5",
            " match community CL-KEY exact-match",
            " match extcommunity RT-KEY RT-SHA",
            " set comm-list CL-KEY delete",
            " set extcomm-list RT-KEY delete",
            " neighbor 10.0.0.2 route-map IN-KEY in",
            " neighbor 10.0.0.2 prefix-list PL-MD5 out",
            " redistribute connected route-map RM-TOKEN metric 10",
            "  export map EXPORT-KEY",
            "  import map IMPORT-MD5",
            " import ipv4 unicast map GLOBAL-KEY",
            "route-policy RP-KEY",
            "  route-policy RP-SHA in",
            "  import route-policy RP-KEY",
            "extcommunity-set rt RT-KEY",
            "community-set CS-MD5",
            "prefix-set PS-TOKEN",
            "  set extcommunity rt RT-KEY additive",
            "  if extcommunity rt matches-any RT-KEY then",
            "  if destination in PS-TOKEN then",
            "    community RT-KEY members target:65000:10;",
            "    community RT-MD5 members [ target:65000:10 target:65000:11 ];",
            "    policy-statement EXP-KEY {",
            "    from community [ RT-KEY RT-MD5 ];",
            "    community add [ RT-KEY RT-MD5 ];",
            "    vrf-import [ IMP-KEY IMP-MD5 ];",
            "    export [ EXP-KEY NEXT ];",
            "set policy-options community RT-KEY members target:65000:10",
            "set policy-options policy-statement EXP-KEY term t1 then community add RT-KEY",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))


    def test_a_secret_on_a_line_that_names_a_policy_is_still_redacted(self):
        for line, kept in (
            # An SNMP community is the secret wherever it stands, and a policy-shaped name is no exception.
            ("snmp-server community RT-KEY RO", "snmp-server community"),
            ("set snmp community RT-KEY authorization read-only", "set snmp community"),
            ("snmp-server community ops-secret RO", "snmp-server community"),
            ("snmp-server host 192.0.2.9 version 2c ops-key udp-port 1162", "snmp-server host 192.0.2.9 version 2c"),
            # A name that is the keyword itself is read as the keyword, as a BGP group's is.
            ("route-map KEY permit 10", "route-map KEY"),
            # What follows a masked name is judged on its own words.
            (" neighbor 10.0.0.2 route-map IN-KEY in password S3cret", " neighbor 10.0.0.2 route-map IN-KEY in password"),
            (" neighbor RR-KEY password S3cret", " neighbor RR-KEY password"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line)[0], f"{kept} {REDACTION_MARKER}")
        self.assertNotIn("S1pub", redact("snmp {\n    community RT-KEY members S1pub;\n}")[0])
        # A Junos community opening its block keeps the brace and loses the name.
        self.assertEqual(redact("snmp {\n    community ops-key {\n        authorization read-only;")[0].splitlines()[1],
                         f"    community {REDACTION_MARKER} {{")


class EveryMailServerLosesItsPassword(unittest.TestCase):
    """C4-02: Call Home names its SMTP relay as an EEM action does, `[user:password@]host`.

    R-1 read the form only after an EEM `action N mail server`, so
    `mail-server relay:X@192.0.2.25 priority 1` under `call-home` kept the
    password, in the raw file and in connect.log.
    """

    def test_a_call_home_mail_server_keeps_its_user_and_host(self):
        for line, expected in (
            (" mail-server relay:S1mail@192.0.2.25 priority 1 secure tls",
             f" mail-server relay:{REDACTION_MARKER}@192.0.2.25 priority 1 secure tls"),
            (" mail-server backup:S2m@il:x@smtp.example.net priority 2",
             f" mail-server backup:{REDACTION_MARKER}@smtp.example.net priority 2"),
            (" transport email mail-server ops:S3mail@192.0.2.26 port 25 use-vrf management",
             f" transport email mail-server ops:{REDACTION_MARKER}@192.0.2.26 port 25 use-vrf management"),
            (' mail server "relay:S4mail@192.0.2.27" priority 1',
             f' mail server "relay:{REDACTION_MARKER}@192.0.2.27" priority 1'),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (expected, 1))

    def test_the_transcript_loses_it_too(self):
        from netstate.collector import redact_transcript

        out = redact_transcript("PE1#show running-config\ncall-home\n mail-server relay:S5mail@192.0.2.25 priority 1\n")
        self.assertNotIn("S5mail", out)
        self.assertIn(" mail-server relay:", out)

    def test_a_mail_server_without_credentials_keeps_every_word(self):
        for line in (
            " mail-server 192.0.2.25 priority 1",
            " mail-server smtp.example.net priority 2 secure tls",
            " mail-server 2001:db8::25 priority 3",
            " transport email mail-server 192.0.2.26 port 25 use-vrf management",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))


class ACommandAnAutomationTypesIsReadAsACommand(unittest.TestCase):
    """C4-03: NX-OS types an EEM action's command unquoted, and Junos an event policy's in quotes on a line of its own.

    C-02 read the command inside IOS's `cli command "..."` only, so
    `action 2.0 cli snmp-server community X group network-operator` on
    NX-OS and `"set snmp community X authorization read-only";` under a
    Junos `change-configuration commands { }` kept the community.
    """

    def test_an_nxos_action_typing_a_command_unquoted(self):
        applet = (
            "event manager applet RESTORE-SNMP\n"
            '  event syslog pattern "SNMP-3-AUTHFAIL"\n'
            "  action 1.0 cli configure terminal\n"
            "  action 2.0 cli snmp-server community S1comm group network-operator\n"
            "  action 3.0 cli snmp-server host 192.0.2.50 traps version 2c S2comm\n"
            "  action 4.0 cli local username ops password 5 S3pass role network-admin\n"
            "  action 5.0 cli show interface brief\n"
        )
        out, changed = redact(applet)
        self.assertEqual(out.splitlines(), [
            "event manager applet RESTORE-SNMP",
            '  event syslog pattern "SNMP-3-AUTHFAIL"',
            "  action 1.0 cli configure terminal",
            f"  action 2.0 cli snmp-server community {REDACTION_MARKER}",
            f"  action 3.0 cli snmp-server host 192.0.2.50 traps version 2c {REDACTION_MARKER}",
            f"  action 4.0 cli local username ops password {REDACTION_MARKER}",
            "  action 5.0 cli show interface brief",
        ])
        self.assertEqual(changed, 3)

    def test_a_junos_event_policy_typing_set_commands(self):
        policy = (
            "event-options {\n"
            "    policy RESTORE-SNMP {\n"
            "        events snmpd_auth_failure;\n"
            "        then {\n"
            "            change-configuration {\n"
            "                commands {\n"
            '                    "set snmp community S4comm authorization read-only";\n'
            '                    "set snmp community \\"S5 comm\\" clients 192.0.2.0/24";\n'
            '                    "set interfaces ge-0/0/0 description uplink";\n'
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            'set event-options policy P2 then change-configuration commands "set snmp community S6comm authorization read-only"\n'
        )
        out, changed = redact(policy)
        lines = out.splitlines()
        self.assertEqual(lines[6], f'                    "set snmp community {REDACTION_MARKER}";')
        self.assertEqual(lines[7], f'                    "set snmp community {REDACTION_MARKER}";')
        self.assertEqual(lines[8], '                    "set interfaces ge-0/0/0 description uplink";')
        self.assertEqual(lines[-1], f'set event-options policy P2 then change-configuration commands "set snmp community {REDACTION_MARKER}"')
        self.assertEqual(changed, 3)
        # The block closes where it did: a community after it is the BGP one it is.
        self.assertIn("community RT members target:65000:1;", redact(policy + "community RT members target:65000:1;")[0])

    def test_the_transcript_loses_them_too(self):
        from netstate.collector import redact_transcript

        out = redact_transcript("LEAF1# show running-config\n  action 2.0 cli snmp-server community S7comm group network-operator\n")
        self.assertNotIn("S7comm", out)


class ALoneEscapeTakesNoLetterWithIt(unittest.TestCase):
    """C4-05: R-4 read ESC and any byte after it as one escape, so a lone ESC took the line's first letter.

    `ESC snmp-server community X RO` became `nmp-server community X RO`,
    which no rule anchored on the keyword reads, and the community reached
    disk. Only the bytes a terminal ends a two-byte escape with are read as
    one; any other ESC goes alone, as before R-4.
    """

    def test_a_lone_escape_in_front_of_a_line_goes_alone(self):
        from netstate.collector import clean_text

        for text, kept in (
            ("\x1bsnmp-server community S1comm RO", "snmp-server community"),
            ("key chain K\n key 1\n\x1b  key-string 7 S2key", "  key-string"),
            ("\x1bsnmp-server host 192.0.2.9 version 2c S3comm", "snmp-server host 192.0.2.9 version 2c"),
            ("router ospf 1\n\x1b ip ospf message-digest-key 1 md5 S4key", " ip ospf message-digest-key"),
            ("\x1busername ops password 0 S5pass", "username ops password"),
            ("snmp {\n\x1b    community S6comm;", "    community"),
            # `ESC c` resets a terminal, but not in front of the rest of a keyword.
            ("snmp {\n\x1bcommunity S7comm;", "community"),
            ("\x1bcak S7cak", "cak"),
        ):
            with self.subTest(text=text):
                # A Junos leaf keeps its `;` (BUG-COLLECTOR-JUNOS-REDACT-SEMICOLON).
                end = ";" if text.endswith(";") else ""
                self.assertEqual(redact(text)[0].splitlines()[-1], f"{kept} {REDACTION_MARKER}{end}")
                self.assertEqual(clean_text(text), text.replace("\x1b", ""))

    def test_the_escapes_a_terminal_sends_still_go_whole(self):
        from netstate.collector import clean_text

        for escape in (
            "\x1b7", "\x1b8", "\x1b=", "\x1b>", "\x1bc", "\x1bD", "\x1bE", "\x1bH", "\x1bM", "\x1bN",
            "\x1bO", "\x1bZ", "\x1b\\", "\x1b(B", "\x1b)0", "\x1b*A", "\x1b+B", "\x1b#8", "\x1b#3",
        ):
            with self.subTest(escape=escape):
                self.assertEqual(clean_text(escape + "snmp-server community S8comm RO"), "snmp-server community S8comm RO")


class EveryCharacterThatPrintsAsNothingIsRemoved(unittest.TestCase):
    """C4-06: the characters cleaned were a list, and a bidi isolate, a tag or a C1 control was not on it.

    One in front of `snmp-server community X`, or inside its keyword, hid
    the line from every rule. Every format character (Unicode category
    Cf) and every control character (Cc) but the tab, the newline and the
    carriage return is removed now, whatever the list would have named.
    """

    MARKS = (
        "⁦", "⁧", "⁨", "⁩", "؜", "᠎", "⁪", "⁯", "\U000e0001", "\U000e0020",
        "؀", "￹", "\U0001d173", "\x80", "\x84", "\x8d", "\x9a", "\x85", "\x7f",
    )

    def test_a_mark_in_front_of_a_line_or_inside_its_keyword_hides_nothing(self):
        for mark in self.MARKS:
            for text in (f"{mark}snmp-server community S1comm RO", f"snmp-server comm{mark}unity S1comm RO"):
                with self.subTest(mark=repr(mark), text=repr(text)):
                    self.assertEqual(redact(text)[0], f"snmp-server community {REDACTION_MARKER}")

    def test_every_format_and_control_character_but_the_layout_is_removed(self):
        import sys
        import unicodedata

        from netstate.collector import clean_text

        hidden = "".join(
            chr(code) for code in range(sys.maxunicode + 1)
            if unicodedata.category(chr(code)) in ("Cf", "Cc") and chr(code) not in "\t\n\r\x1b\x9b\x90\x98\x9c\x9d\x9e\x9f"
        )
        self.assertEqual(clean_text(f"a{hidden}b"), "ab")
        self.assertEqual(clean_text("a\tb\r\nc é ü ß 中  "), "a\tb\r\nc é ü ß 中  ")


class AnSshAlgorithmListIsNoSecret(unittest.TestCase):
    """R1: an SSH algorithm list lost every name after the first one ending in `sha1`, `md5` or `key`.

    `hmac-sha1`, `diffie-hellman-group14-sha256` and IOS-XR's head
    `host-key` end in a keyword, and the keyword rule took the names after
    them for its value: `ip ssh server algorithm mac hmac-sha1 hmac-sha2-256`
    kept one MAC of two, and Junos's `macs [ hmac-sha1 hmac-sha2-256 ];` lost
    its bracket too, so an assessment could not say what the server offers.
    A statement whose every word after its head is a name that head takes is
    kept whole; one word that is not, and the line is cut as before.
    """

    def assert_kept(self, lines):
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_an_ios_xe_server_or_client_list_keeps_every_name(self):
        self.assert_kept((
            "ip ssh server algorithm mac hmac-sha1 hmac-sha2-256 hmac-sha2-512",
            "ip ssh server algorithm mac hmac-sha2-512-etm@openssh.com hmac-sha1 hmac-sha2-256-etm@openssh.com",
            "ip ssh server algorithm kex diffie-hellman-group14-sha1 ecdh-sha2-nistp256 curve25519-sha256@libssh.org",
            "ip ssh server algorithm kex diffie-hellman-group16-sha512 diffie-hellman-group14-sha256",
            "ip ssh server algorithm encryption aes256-gcm aes256-ctr aes128-gcm@openssh.com chacha20-poly1305@openssh.com",
            "ip ssh server algorithm hostkey rsa-sha2-512 rsa-sha2-256 x509v3-ssh-rsa ssh-rsa",
            "ip ssh server algorithm publickey x509v3-ecdsa-sha2-nistp256 ecdsa-sha2-nistp384 ssh-rsa",
            "ip ssh server algorithm authentication password keyboard publickey",
            "ip ssh client algorithm mac hmac-sha1 hmac-sha2-256",
            "ip ssh client algorithm kex diffie-hellman-group14-sha1 ecdh-sha2-nistp521",
        ))

    def test_an_ios_xr_server_or_client_list_keeps_every_name(self):
        self.assert_kept((
            "ssh server algorithms key-exchange diffie-hellman-group14-sha1 ecdh-sha2-nistp256 ecdh-sha2-nistp384",
            "ssh server algorithms host-key ecdsa-nistp256 ed25519 rsa dsa x509v3-ssh-rsa",
            "ssh server algorithms host-key rsa",
            "ssh server algorithms mac hmac-sha1 hmac-sha2-256 hmac-sha2-512",
            "ssh server algorithms cipher aes256-ctr aes192-ctr aes256-gcm@openssh.com",
            "ssh client algorithms key-exchange diffie-hellman-group14-sha256 curve25519-sha256",
        ))

    def test_an_nxos_list_or_its_level_keeps_every_word(self):
        self.assert_kept((
            "ssh macs hmac-sha1 hmac-sha2-256 hmac-sha2-512",
            "ssh kexalgos diffie-hellman-group14-sha1 ecdh-sha2-nistp256 curve25519-sha256@libssh.org",
            "ssh keytypes ssh-rsa rsa-sha2-256 ecdsa-sha2-nistp256",
            "ssh ciphers aes256-gcm@openssh.com aes256-ctr",
            "ssh macs all",
            "ssh kexalgos all",
        ))

    # Junos's heads say `ssh` only through the stanza they stand in.
    JUNOS_SSH = "system {\n    services {\n        ssh {\n"

    def test_a_junos_list_or_single_name_keeps_every_word_and_its_bracket(self):
        self.assert_kept(tuple(self.JUNOS_SSH + line for line in (
            "            macs [ hmac-sha1 hmac-sha2-256 hmac-md5-96 umac-64@openssh.com ];",
            "            macs [ hmac-sha2-256 hmac-sha1 ];",
            "            key-exchange [ dh-group14-sha1 ecdh-sha2-nistp256 group-exchange-sha2 curve25519-sha256 ];",
            "            key-exchange dh-group14-sha1;",
            "            ciphers [ aes256-ctr aes256-gcm@openssh.com 3des-cbc ];",
            "            macs hmac-sha1;",
            "            inactive: macs [ hmac-md5 hmac-sha1 ];",
            "            hostkey-algorithm ssh-ecdsa;",
        )))

    def test_a_junos_list_outside_the_ssh_stanza_is_cut_as_before(self):
        for config, kept in (
            ("macs [ hmac-sha1 hmac-sha2-256 ];", "macs [ hmac-sha1"),
            ("system {\n    services {\n        key-exchange [ dh-group14-sha1 ecdh-sha2-nistp256 ];",
             "system {\n    services {\n        key-exchange [ dh-group14-sha1"),
            # A block opened inside `ssh` is not `ssh`.
            (self.JUNOS_SSH + "            hostkey-algorithm {\n                macs [ hmac-sha1 hmac-sha2-256 ];",
             self.JUNOS_SSH + "            hostkey-algorithm {\n                macs [ hmac-sha1"),
            # Closed again, so what follows it is not in it.
            (self.JUNOS_SSH + "        }\n        macs [ hmac-sha1 hmac-sha2-256 ];",
             self.JUNOS_SSH + "        }\n        macs [ hmac-sha1"),
        ):
            with self.subTest(config=config):
                self.assertEqual(redact(config), (f"{kept} {REDACTION_MARKER}", 1))

    def test_an_asa_key_exchange_or_cipher_setting_keeps_every_word(self):
        self.assert_kept((
            "ssh key-exchange group curve25519-sha256 ecdh-group21 dh-group14-sha256",
            "ssh key-exchange group dh-group14-sha1",
            "ssh key-exchange group ecdh-group19",
            "ssh cipher encryption high",
            "ssh cipher integrity fips",
            "ssh cipher integrity custom hmac-sha1:hmac-sha2-256",
            'ssh cipher integrity custom "hmac-sha2-256:hmac-sha1"',
            'ssh cipher encryption custom "aes256-ctr:aes128-ctr"',
        ))

    def test_a_list_with_a_word_that_is_no_algorithm_name_is_cut_as_before(self):
        for line, kept in (
            # A secret typed after the list, or in it.
            ("ip ssh server algorithm mac hmac-sha1 S3CRET", "ip ssh server algorithm mac hmac-sha1"),
            ("ip ssh server algorithm mac hmac-sha1 hmac-sha2-256 S3CRET", "ip ssh server algorithm mac hmac-sha1"),
            ("ip ssh server algorithm kex diffie-hellman-group14-sha1 password S3CRET",
             "ip ssh server algorithm kex diffie-hellman-group14-sha1"),
            ("ip ssh server algorithm authentication password S3CRET", "ip ssh server algorithm authentication password"),
            ("ssh server algorithms host-key rsa S3CRET", "ssh server algorithms host-key"),
            ("ssh macs hmac-sha1 hmac-sha2-256 key S3CRET", "ssh macs hmac-sha1"),
            ("            macs [ hmac-sha1 S3CRET ];", "            macs [ hmac-sha1"),
            ("            macs hmac-sha1 S3CRET;", "            macs hmac-sha1"),
            ("ssh key-exchange group dh-group14-sha256 S3CRET", "ssh key-exchange group dh-group14-sha256"),
            ("ssh cipher integrity high hmac-sha1 S3CRET", "ssh cipher integrity high hmac-sha1"),
            # A quoted string that is no colon-separated list of names.
            ('ssh cipher integrity custom "hmac-sha1 S3CRET"', 'ssh cipher integrity custom "hmac-sha1'),
            # A name the head does not take: a cipher in a list of MACs, a
            # level beside a list, IOS-XR's short host keys under another head.
            ("ip ssh server algorithm mac hmac-sha1 aes256-ctr", "ip ssh server algorithm mac hmac-sha1"),
            ("ssh macs hmac-sha1 all", "ssh macs hmac-sha1"),
            ("ip ssh server algorithm kex diffie-hellman-group14-sha1 rsa",
             "ip ssh server algorithm kex diffie-hellman-group14-sha1"),
            # A head no platform has, spelled like one.
            ("ssh server algorithms macs hmac-sha1 hmac-sha2-256", "ssh server algorithms macs hmac-sha1"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))

    def test_a_junos_ssh_stanza_keeps_its_lists_and_its_braces(self):
        from netstate.readers import junos_paths

        config = (
            "system {\n    services {\n        ssh {\n            root-login deny;\n"
            "            macs [ hmac-sha2-256 hmac-sha1 ];\n"
            "            key-exchange [ dh-group14-sha1 ecdh-sha2-nistp256 ];\n"
            "        }\n    }\n    root-authentication {\n"
            '        encrypted-password "$6$S3CRET"; ## SECRET-DATA\n    }\n}'
        )
        out, changed = redact(config)
        self.assertEqual(changed, 1)
        self.assertNotIn("$6$", out)
        paths = junos_paths(out)
        self.assertIn(["system", "services", "ssh", "macs [ hmac-sha2-256 hmac-sha1 ]"], paths)
        self.assertIn(["system", "services", "ssh", "key-exchange [ dh-group14-sha1 ecdh-sha2-nistp256 ]"], paths)
        self.assertIn(["system", "root-authentication"], paths)


class AJunosConfigurationGroupNamedWithAKeywordIsAName(unittest.TestCase):
    """R2: `apply-groups [ ISIS-MD5 RR-KEY BASE ];` lost every group after the first.

    A configuration group is named by the operator, and `ISIS-MD5`,
    `RR-KEY` or `NTP-SECRET` ends in a keyword: read as one, the keyword
    took every name after it and the closing bracket, so which groups a
    level of the hierarchy takes could not be read. The list is a name
    now, masked as a policy's is. The group's own definition, `ISIS-MD5 {`,
    keeps its brace as it always did, so the block still opens and closes.
    """

    def test_an_apply_groups_list_keeps_every_name(self):
        for line in (
            "apply-groups [ ISIS-MD5 RR-KEY BASE ];",
            "    apply-groups [ BASE NTP-SECRET ];",
            "    apply-groups-except [ NTP-SECRET RR-KEY ];",
            "    apply-groups ISIS-MD5;",
            "    apply-groups-except RR-KEY;",
            "set system apply-groups [ ISIS-MD5 BASE ]",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_group_s_definition_keeps_its_name_and_brace(self):
        for line in (
            "    ISIS-MD5 {",
            "    inactive: RR-KEY {",
            "    protect: NTP-SECRET {",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_the_groups_and_the_list_that_applies_them_read_back_whole(self):
        from netstate.readers import junos_paths

        config = (
            "groups {\n    ISIS-MD5 {\n        protocols {\n            isis {\n"
            "                level 2 authentication-type md5;\n            }\n        }\n    }\n"
            "    RR-KEY {\n        protocols {\n            bgp {\n                group IBGP {\n"
            "                    cluster 192.0.2.1;\n                }\n            }\n        }\n    }\n}\n"
            "apply-groups [ ISIS-MD5 RR-KEY BASE ];\n"
            "system {\n    host-name PE1;\n}"
        )
        out, changed = redact(config)
        self.assertEqual((out, changed), (config, 0))
        # The text as written: the groups resolved (G02) would read back as protocols.
        paths = junos_paths(out, inherit=False)
        self.assertIn(["groups", "ISIS-MD5", "protocols", "isis", "level 2 authentication-type md5"], paths)
        self.assertIn(["groups", "RR-KEY", "protocols", "bgp", "group IBGP", "cluster 192.0.2.1"], paths)
        self.assertIn(["apply-groups [ ISIS-MD5 RR-KEY BASE ]"], paths)
        self.assertIn(["system", "host-name PE1"], paths)
        # And resolved, both groups give what they hold where they apply.
        resolved = junos_paths(out)
        self.assertIn(["protocols", "isis", "level 2 authentication-type md5"], resolved)
        self.assertIn(["protocols", "bgp", "group IBGP", "cluster 192.0.2.1"], resolved)

    def test_a_secret_beside_a_group_name_is_still_redacted(self):
        for line, expected in (
            # What follows the masked list is judged on its own words.
            ("apply-groups [ ISIS-MD5 ] password S3CRET", f"apply-groups [ ISIS-MD5 ] password {REDACTION_MARKER}"),
            # A name that is the keyword itself is read as the keyword.
            ("apply-groups password S3CRET", f"apply-groups password {REDACTION_MARKER}"),
            # A block line with more than its name before the brace.
            ("    ISIS-MD5 S3CRET {", f"    ISIS-MD5 {REDACTION_MARKER} {{"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (expected, 1))

    def test_a_keyword_standing_alone_inside_a_list_is_the_keyword(self):
        # A list in brackets is one name, but the word the keyword ends is
        # what says whether it is the keyword: read from the `[`, `[ x
        # password` was never the keyword alone, and the word after it stayed.
        for line, expected in (
            ("apply-groups [ x password hunter2 ];", f"apply-groups [ x password {REDACTION_MARKER}"),
            ("apply-groups [ secret hunter2 ];", f"apply-groups [ secret {REDACTION_MARKER}"),
            ("vrf-import [ RT-A password hunter2 ];", f"vrf-import [ RT-A password {REDACTION_MARKER}"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (expected, 1))
        for line in ("apply-groups [ ISIS-MD5 RR-KEY BASE ];", "vrf-import [ RT-KEY RT-MD5 ];"):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_keyword_of_more_than_one_word_inside_a_name_list_is_the_keyword(self):
        # Matched by its last word alone, `authentication text` was no
        # keyword, the list was masked as a name and the secret after it kept.
        for line, kept in (
            ("match community authentication text S3CR3T", "match community authentication text"),
            ("match community standby 1 authentication S3CR3T", "match community standby 1 authentication"),
            ("match community wpa-psk ascii 0 S3CR3T", "match community wpa-psk ascii 0"),
            ("match as-path key-octet-string 7 S3CR3T", "match as-path key-octet-string 7"),
            ("match community esp aes 256 S3CR3T", "match community esp aes 256"),
            ("apply-groups [ authentication text S3CR3T ];", "apply-groups [ authentication text"),
            ("apply-groups [ hmac-sha-1 7 S3CR3T ];", "apply-groups [ hmac-sha-1 7"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))

    def test_an_annotation_after_a_group_s_brace_goes_and_the_brace_stays(self):
        from netstate.readers import junos_paths

        for annotation in ("## password hunter2", "/* password hunter2 */", "## Warning: 'x' is deprecated"):
            config = f"groups {{\n    NTP-SECRET {{ {annotation}\n        system;\n    }}\n}}"
            with self.subTest(annotation=annotation):
                out, changed = redact(config)
                self.assertEqual(out, "groups {\n    NTP-SECRET {\n        system;\n    }\n}")
                self.assertEqual(changed, 1)
                self.assertIn(["groups", "NTP-SECRET", "system"], junos_paths(out))


class AnIsisSendOnlyModeIsNoSecret(unittest.TestCase):
    """R3: IOS-XE's `authentication send-only` under `router isis` read as an HSRP string.

    IOS-XR writes an HSRP group's plain-text string as a bare
    `authentication X`, so one word after `authentication` is redacted
    unless it is a mode. `send-only` is one: the router sends the key its
    key chain holds and does not yet check what arrives.
    """

    def test_every_send_only_form_keeps_every_word(self):
        for config in (
            "router isis CORE\n authentication send-only",
            "router isis CORE\n authentication send-only level-1",
            "router isis CORE\n authentication send-only level-2",
            "router isis CORE\n authentication mode md5\n authentication key-chain ISIS-KC\n authentication send-only",
            "interface GigabitEthernet2\n isis authentication send-only",
            "interface GigabitEthernet2\n isis authentication send-only level-1",
            "interface GigabitEthernet2\n isis authentication send-only level-2",
        ):
            with self.subTest(config=config):
                self.assertEqual(redact(config), (config, 0))

    def test_a_string_that_only_starts_like_it_still_goes(self):
        for config in ("hsrp 1\n authentication send-only1", "hsrp 1\n authentication S3CRET"):
            with self.subTest(config=config):
                self.assertEqual(redact(config), (f"hsrp 1\n authentication {REDACTION_MARKER}", 1))

    def test_send_only_is_a_mode_only_under_router_isis(self):
        # Under anything else it is read as the string a bare
        # `authentication` gives there: IOS-XR's HSRP group's.
        config = ("router hsrp\n interface GigabitEthernet0/0/0/0\n  address-family ipv4\n"
                  "   hsrp 1\n    authentication send-only")
        out, changed = redact(config)
        self.assertEqual(out.splitlines()[-1], f"    authentication {REDACTION_MARKER}")
        self.assertEqual(changed, 1)


class AnXrIsisPasswordLosesOnlyThePassword(unittest.TestCase):
    """R4: IOS-XR's `lsp-password hmac-md5 encrypted X level 2` lost its mode, its level and `send-only`.

    Cut at the keyword, a key and a clear-text password read the same, and
    so did a level that checks what it receives and one that only sends. In
    exactly the shape `(lsp|hello)-password hmac-md5|text encrypted|clear X
    [level 1|2] [send-only] [enable-poi]` only X goes; any other shape is
    cut at the keyword as before.
    """

    def test_the_mode_and_the_options_stay_and_the_password_goes(self):
        for line, kept, rest in (
            (" lsp-password hmac-md5 encrypted 0822455D0A16 level 2", " lsp-password hmac-md5 encrypted", " level 2"),
            (" lsp-password text encrypted 1304131F0202", " lsp-password text encrypted", ""),
            (" lsp-password hmac-md5 clear Pa55w0rd level 1 send-only", " lsp-password hmac-md5 clear",
             " level 1 send-only"),
            (" lsp-password hmac-md5 encrypted 0822455D0A16 level 2 send-only enable-poi",
             " lsp-password hmac-md5 encrypted", " level 2 send-only enable-poi"),
            (" lsp-password hmac-md5 encrypted 0822455D0A16 enable-poi", " lsp-password hmac-md5 encrypted", " enable-poi"),
            ("  hello-password hmac-md5 encrypted 1304131F0202 send-only", "  hello-password hmac-md5 encrypted",
             " send-only"),
            ("  hello-password text clear Pa55w0rd level 2", "  hello-password text clear", " level 2"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}{rest}", 1))

    def test_a_line_of_any_other_shape_is_cut_at_the_keyword(self):
        for line, kept in (
            (" lsp-password accept encrypted 0822455D0A16 level 2", " lsp-password"),
            (" lsp-password hmac-md5 encrypted 0822455D0A16 level 3", " lsp-password"),
            (" lsp-password hmac-md5 encrypted 0822455D0A16 S3CRET", " lsp-password"),
            (' lsp-password text clear "Pa55 w0rd" level 2', " lsp-password"),
            (" lsp-password hmac-md5 0822455D0A16 level 2", " lsp-password"),
            (" lsp-password 0822455D0A16", " lsp-password"),
            ("  hello-password sha-256 encrypted 1304131F0202", "  hello-password"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))

    def test_the_keychain_form_is_kept_whole(self):
        for line in (
            " lsp-password keychain ISIS-KC level 2 send-only",
            "  hello-password keychain ISIS-KC send-only",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_brace_is_never_the_password(self):
        # Taken for one, the brace was dropped before the blocks were
        # tracked, so the next `}` closed `snmp` and its community stood
        # outside it.
        config = "snmp {\n lsp-password text clear {\n }\n community hunter2;\n}"
        out, _ = redact(config)
        self.assertNotIn("hunter2", out)
        self.assertEqual(out.splitlines()[1], f" lsp-password {REDACTION_MARKER} {{")


class ASwitchThatGivesNoSecretKeepsEveryWord(unittest.TestCase):
    """R5: NX-OS's `ssh key rsa 2048` and `password strength-check`, and `password encryption aes`, carry no secret.

    The keyword rule read `key` and `password` and took what follows:
    `ssh key <REDACTED>` hid the host key's type and size, and `no password
    <REDACTED>` whether the strength check was turned off. Only these
    shapes are kept whole; a word more and the line is cut as before.
    """

    def test_each_shape_is_kept_whole(self):
        for line in (
            "ssh key rsa 2048",
            "ssh key rsa 4096 force",
            "ssh key rsa",
            "ssh key dsa",
            "ssh key dsa force",
            "ssh key ecdsa 521",
            "ssh key ecdsa 384 force",
            "password strength-check",
            "no password strength-check",
            "feature password encryption aes",
            "password encryption aes",
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (line, 0))

    def test_a_word_more_or_another_word_and_the_line_is_cut_as_before(self):
        for line, kept in (
            ("ssh key rsa 2048 S3CRET", "ssh key"),
            ("ssh key rsa S3CRET", "ssh key"),
            ("ssh key rsa 204800", "ssh key"),
            ("ssh key S3CRET", "ssh key"),
            ("password strength-check S3CRET", "password"),
            ("no password S3CRET", "no password"),
            ("password encryption aes S3CRET", "password"),
            ("feature password encryption S3CRET", "feature password"),
            ("key config-key password-encrypt S3CRET", "key"),
        ):
            with self.subTest(line=line):
                self.assertEqual(redact(line), (f"{kept} {REDACTION_MARKER}", 1))

    def test_indented_it_is_a_line_s_password_and_goes(self):
        # IOS takes the rest of the line as a line's password, spaces and
        # all: under `line vty 0 4` these words are the password.
        for parent in ("line vty 0 4", "line con 0", "l2tp-class L2"):
            for setting in ("password strength-check", "password encryption aes", "no password strength-check"):
                config = f"{parent}\n {setting}"
                with self.subTest(config=config):
                    kept = "no password" if setting.startswith("no") else "password"
                    self.assertEqual(redact(config), (f"{parent}\n {kept} {REDACTION_MARKER}", 1))

    def test_typed_by_an_automation_or_in_a_macro_it_may_be_a_line_s_password_and_goes(self):
        # Neither has the indentation that tells a global command from a
        # line's password: the applet types `line vty 0 4` first, and a
        # macro's body stands at the start of the line up to its `@`.
        applet = ('event manager applet SETPW\n action 3.0 cli command "line vty 0 4"\n'
                  ' action 4.0 cli command "password strength-check"')
        out, changed = redact(applet)
        self.assertEqual(out.splitlines()[-1], f' action 4.0 cli command "password {REDACTION_MARKER}"')
        self.assertEqual(changed, 1)
        macro = "macro name SETPW\nline vty 0 4\npassword encryption aes\n@\npassword encryption aes"
        self.assertEqual(
            redact(macro),
            (f"macro name SETPW\nline vty 0 4\npassword {REDACTION_MARKER}\n@\npassword encryption aes", 1),
        )


class TheLinesKeptWholeAreNotCounted(unittest.TestCase):
    """R1-R5: what `redact` counts is the lines it changed, and a line kept whole is none of them."""

    def test_a_configuration_mixing_kept_and_cut_lines_counts_only_the_cut(self):
        config = (
            "ip ssh server algorithm mac hmac-sha1 hmac-sha2-256\n"
            "ip ssh server algorithm kex diffie-hellman-group14-sha1 ecdh-sha2-nistp256\n"
            "password encryption aes\n"
            "username ops secret 9 $9$S3CRET\n"
            "router isis CORE\n"
            " authentication send-only\n"
            " lsp-password hmac-md5 encrypted 0822455D0A16 level 2\n"
            " lsp-password accept encrypted 0822455D0A16\n"
            "ssh key rsa 2048\n"
            "ssh macs hmac-sha1 hmac-sha2-256 S3CRET\n"
        )
        out, changed = redact(config)
        lines = list(zip(config.splitlines(), out.splitlines()))
        self.assertEqual(changed, sum(source != redacted for source, redacted in lines))
        self.assertEqual(changed, 4)
        self.assertNotIn("S3CRET", out)
        self.assertNotIn("0822455D0A16", out)


# G32 (BUG-COLLECTOR-EAP-MD5-CUT): an IKEv2 profile's EAP lines, kept out of
# FRAGMENTS so the fragments' pinned digest (test_banner_stanzas) stays
# where it was. Pinned line by line, as the fragments are.
IKEV2_EAP = """\
crypto ikev2 profile P-EAP
 authentication local eap md5 username U1 password 0 Pa55w0rd
 authentication local eap md5 username U1
 authentication remote eap md5 password 6 Pa55w0rd
 authentication local eap md5 username md5 password Pa55w0rd
 authentication local eap md5 Pa55w0rd
 authentication local eap gtc username U1 password Pa55w0rd
 authentication remote eap query-identity
 authentication local pre-share key 6 Pa55w0rd
crypto isakmp policy 10
 hash md5
"""
IKEV2_EAP_EXPECTED = f"""\
crypto ikev2 profile P-EAP
 authentication local eap md5 username U1 password {REDACTION_MARKER}
 authentication local eap md5 username U1
 authentication remote eap md5 password {REDACTION_MARKER}
 authentication local eap md5 username md5 {REDACTION_MARKER}
 authentication local eap md5 {REDACTION_MARKER}
 authentication local eap gtc username U1 password {REDACTION_MARKER}
 authentication remote eap query-identity
 authentication local pre-share key {REDACTION_MARKER}
crypto isakmp policy 10
 hash md5
"""


class AnEapMd5MethodIsNoSecret(unittest.TestCase):
    """G32: `eap md5` in an IKEv2 profile is the EAP method; what follows `password` is the secret."""

    def test_the_lines_redact_as_pinned(self):
        out, changed = redact(IKEV2_EAP)
        self.assertEqual(out.splitlines(), IKEV2_EAP_EXPECTED.splitlines())
        self.assertEqual(changed, 6)
        self.assertNotIn("Pa55w0rd", out)
        self.assertEqual(redact(out), (out, 0))


if __name__ == "__main__":
    unittest.main()
