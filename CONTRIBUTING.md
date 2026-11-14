# Contributing

Thank you for helping. The Collector's job is narrow on purpose: log in, send
only allowlisted `show` commands, redact, store, export, verify. Changes that
keep it that way are welcome; changes that widen what it sends to a device
are reviewed hard and most will be declined.

## The rules a change must keep

1. **Read-only is absolute.** `netstate/commands.yaml` is the only source of
   device commands. Never add a command that is not a `show` command (or the
   platform's equivalent form the allowlist already uses). Probes stay
   `ping` only, to addresses the collection itself learned.
2. **No real network in the repository.** No configuration, output, hostname,
   address or name taken from a real network, yours or anyone's. Write
   fixtures by hand, with addresses from documentation space (`192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and hostnames in the
   made-up convention `netstate/naming.py` documents. `tests/test_hygiene.py`
   fails on anything else.
3. **Every change gets a test**, and the suite stays green offline: no
   device, no network.
4. **Documentation tells the truth.** Make no claim in the README beyond what
   a test or a run against a device shows.

## Running the tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -c constraints/py3.12.txt -e .   # on 3.11: constraints/py3.11.txt
python -m unittest discover -s tests -t .
```

## Adding a platform or a command

Add the command to `netstate/commands.yaml` under the platform's `parse`,
`raw_only` or a `features` group, with a hand-written sample of its output as
a test fixture. If redaction must learn the platform's syntax for a secret,
add the case to `tests/test_redaction_battery.py` first and watch it fail.

## Sign your work: the Developer Certificate of Origin

Every commit in a pull request must carry a `Signed-off-by:` line with your
real name and an email you can be reached at, certifying the Developer
Certificate of Origin 1.1 below. `git commit -s` adds it. A pull request with
a commit that has none cannot be merged. CI checks each commit's sign-off
against its author's email; `tools/check_dco.sh origin/main HEAD` runs the
same check before you push.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Contributions are licensed under Apache-2.0, the repository's licence.

## Reporting a security problem

Not in an issue: see [SECURITY.md](SECURITY.md).
