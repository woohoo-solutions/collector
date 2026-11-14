# DiscoNet Collector

Read-only collection of network device state. The Collector logs in to
routers, switches and firewalls over SSH, sends only the `show` commands in
one allowlist, replaces secrets as each answer arrives, and keeps the result
on your machine. It can pack that result into one archive with a SHA-256 hash
per file, and check such an archive.

It is the collection engine of [DiscoNet](https://woohoo-solutions.com), a
network documentation service by WooHoo OÜ. The Python package is `netstate`;
the distribution on PyPI is `disconet-collector`. Licensed under Apache-2.0.

Platforms (the testbed's `os:` values): `iosxe` (Cisco IOS-XE), `ios` (classic
IOS), `iosxr` (IOS-XR), `nxos` (NX-OS), `asa` (ASA) and `junos` (Juniper
Junos).

## The read-only rules

1. **The allowlist is the only source of commands.** Every command the
   Collector may send is in one file,
   [`netstate/commands.yaml`](netstate/commands.yaml), per operating system.
   The file is checked when it loads: an entry that is not a `show` command,
   or that contains a configuration verb (`configure`, `write`, `copy`,
   `erase`, `delete`, `reload`, `clear` and others), stops the run before any
   device is contacted. Each command is checked again against the loaded list
   immediately before it is sent. The manifest records the SHA-256 of the
   allowlist the run used, and `verify` compares it with the file you were
   given.
2. **Besides the allowlist**, each session sends its terminal setup, fixed per
   platform in the code: `terminal length 0` and `terminal width 0` (NX-OS:
   `width 511`), `set cli screen-length 0` and `screen-width 0` on Junos, and
   `terminal pager 0` on the ASA. On IOS-XE, IOS and ASA the session sends
   `enable`. If your AAA authorizes each command, allow these too.
3. **It never enters configuration mode.** The list of configuration commands
   passed to the SSH library is forced empty, and no code path builds one.
4. **It never accepts a host key by itself.** Every SSH session runs with
   `StrictHostKeyChecking=yes` against one `known_hosts` file beside the
   testbed. A new key is pinned only when an engineer at the terminal compares
   its fingerprint and types `y`. A changed key is refused. Behind a jump host,
   the jump host's own SSH client checks the device keys.
5. **It sends nothing anywhere except to your devices.** No telemetry, no
   upload. An archive leaves only when you send it.

**Off by default:**

| Option | What it does |
|---|---|
| `--verify-reachability` | Reachability probes. The only form is `ping <address>`, and the address must be one the collection itself learned from a dynamic ARP or IPv6 neighbor entry. |
| `--allow-legacy-ssh` | When a device's SSH refuses to negotiate, log in again with the legacy algorithms it offers (SHA-1 key exchange, `ssh-rsa`, CBC). Without it, the refusal is reported. It does not govern the short-key login below. |
| `--allow-telnet` | Where SSH cannot work and TCP/23 answers, log in over Telnet, which sends the login in the clear. Without it, the Collector does not retry over a weaker login. A device the testbed declares as Telnet is logged into over Telnet either way. |
| `--crawl` | Follow CDP/LLDP neighbors to switches not in the testbed, only inside the subnets given with `--crawl-scope`. |

**One weaker login that is on by default:** a device whose RSA host key is
under 1024 bits, which OpenSSH refuses outright and old IOS generates by
default. The Collector logs in to it through its own SSH client
(`disconet-ssh`, built on asyncssh), held to the same pinned host key, with
the same read-only commands. Through that client the device is also offered
the legacy algorithms an old image may need (SHA-1 key exchange, CBC ciphers,
`hmac-md5`, `ssh-rsa`, `ssh-dss`), after the modern ones, whether or not
`--allow-legacy-ssh` is given. A key that short is weak cryptography, so the
collect table and the manifest name the device and its key size: fix it on the
device. A device behind a jump host is not covered.

## Redaction, and its limits

Secrets are replaced as each answer arrives, before anything is written to
disk. A replaced value reads `<REDACTED BY DISCONET>`.

**Replaced:** what follows `password`, `secret`, `key`, `key-string`,
`token`, an SNMP `community`, MD5 and SHA authentication keys, pre-shared
keys, ESP keys, HSRP, VRRP and GLBP authentication, NHRP authentication, WPA
pre-shared keys and IOS-XE's licensing and registration tokens, in the syntax
of each platform. A key chain's *name* is kept and its key is replaced. Hashed
secrets are replaced as well.

**Descriptions and banners** are free text and keep their words, except what
follows `password`, `passwd`, `pwd`, `psk`, `secret` or `community`. So
`description Key Account uplink` is kept whole, and `description guest wifi
password Welcome1` loses `Welcome1`.

**The SSH transcript** is the one file that holds a login in the clear. It is
written with mode 600 (your account only) while the session runs, redacted
into `connect.log` the moment the session ends, and the clear file is deleted
on every exit. No log or transcript is ever exported.

**Limits.**

1. Redaction is a set of patterns, line by line. A secret typed where no
   keyword precedes it survives, for example `description wifi Welcome1`, a
   password in a site name or a key pasted into a banner.
2. It is tuned for the platforms above. A command another vendor prints in a
   different syntax is not covered.
3. User names are kept, in the configuration and in the exported testbed. So
   are names, email addresses and phone numbers that operators wrote in
   descriptions, contacts, banners and SNMP location strings.
4. It can remove more than it needs to: harmless words after `secret` in a
   description are removed as well.

So read the redacted text before you send it anywhere:

```bash
S=snapshots/<id>
grep -n 'REDACTED BY DISCONET' $S/*/raw/*.txt | less        # what was replaced
grep -niE 'password|secret|key|community|token' $S/*/raw/*.txt | grep -v 'REDACTED BY' | less
```

## Quick start

Linux with Python 3.11 or 3.12, or Windows through WSL2 (pyATS does not run on
Windows itself). macOS is not supported.

```bash
python3 -m venv ~/collector-venv && source ~/collector-venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install disconet-collector
disconet-collector --version
```

Write a pyATS testbed, `testbed.yaml`. Keep passwords out of it: `%ENV{}`
reads them from the environment.

```yaml
testbed:
  name: lab
  credentials:
    default:
      username: "%ENV{DISCONET_USERNAME}"
      password: "%ENV{DISCONET_PASSWORD}"
    enable:
      password: "%ENV{DISCONET_ENABLE_PASSWORD}"
devices:
  R1:
    os: iosxe
    connections:
      cli:
        protocol: ssh
        ip: 192.0.2.11
  R2:
    os: junos
    connections:
      cli:
        protocol: ssh
        ip: 192.0.2.12
```

Collect, read the redacted text, export, verify:

```bash
read -rp 'Username: ' DISCONET_USERNAME && export DISCONET_USERNAME
read -rsp 'Password: ' DISCONET_PASSWORD && export DISCONET_PASSWORD; echo
read -rsp 'Enable password: ' DISCONET_ENABLE_PASSWORD && export DISCONET_ENABLE_PASSWORD; echo
disconet-collector collect --testbed testbed.yaml      # writes snapshots/<id>/; asks to pin each new host key
disconet-collector export --testbed testbed.yaml       # the newest snapshot, into one .export.tar.gz beside it
disconet-collector verify snapshots/<id>.export.tar.gz
```

`collect` exits 0 when every device answered, 1 when some did not (the
snapshot is usable but partial), and 2 on a configuration error. `disconet-collector
collect --help` lists the options: `--devices`, `--features`, timeouts,
workers, `--session-log` and the opt-ins above. `python -m netstate` is the
same command.

## What the export holds

One `.export.tar.gz` file holds only the collection:

- `manifest.json`, the record of the run (devices, platforms, features,
  times, and the SHA-256 of the allowlist);
- per device, the redacted raw text (`raw/*.txt`) and the parsed state
  (`state/*.json`);
- `testbed.yaml` with every secret replaced (device names, addresses and user
  names kept);
- `export-manifest.json`, with the SHA-256 of every member, and the optional
  Ed25519 signature over it (`export --sign`).

The run's manifest decides what goes in; other files in the snapshot are
left out. Logs and transcripts, `.env` and `known_hosts` are refused even if
a manifest names them. The full configurations are in it, minus their
secrets: treat the file as you would a configuration backup. `verify` checks
every hash, that only the collection is inside, that the testbed holds no
credential, the allowlist hash and the signature. It needs no device and no
pyATS.

Encrypt the archive to the recipient's public key (age or GPG) before it
travels, never to a password that would have to travel too.

## What it does not do

- **It does not write documents.** No topology, diagrams, tables or prose:
  that is DiscoNet's service, which runs on the export, not in this package.
- **It sends nothing to a language model**, or to anything else but your
  devices.
- **It does not sweep subnets or write the testbed for you.** DiscoNet's
  `setup` and `discover` are not part of this package; you list the devices.
- **It does not change configuration**, and apart from the short-key login
  above it does not decide on a weaker login by itself (see the opt-ins).
- **It does not encrypt the archive.** You do, to the recipient's key.

## Status

The engine is DiscoNet's collector, released here with its tests. The
`disconet-collector` command line is new in this release; in this repository it has run
against fixtures and test doubles, not yet against a device. The short-key
client has logged in end to end, in the test suite, to a local SSH server
offering only what old IOS offers (a 512-bit RSA key, Diffie-Hellman group 1,
`ssh-rsa`, CBC); it has not yet met a device. Export and
verify are built and tested on fixtures and on DiscoNet's synthetic demo
network; they have not yet run on a collection from a real network.

## Development

```bash
pip install -c constraints/py3.12.txt -e .   # on 3.11: constraints/py3.11.txt
python -m unittest discover -s tests -t .
```

The tests run offline: no device, no network. `tests/test_hygiene.py` fails
on any address outside documentation space and a few named textbook examples,
and on any hostname outside the made-up convention documented in
`netstate/naming.py`, so no real network reaches the repository.
Contributions are welcome under the DCO: see [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports: see [SECURITY.md](SECURITY.md).
