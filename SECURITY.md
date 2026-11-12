# Security policy

The Collector logs in to network devices with the operator's credentials, so
a flaw in it matters. We want to hear about one.

## Reporting a vulnerability

Email **info@woohoo-solutions.com** with "Collector security" in the subject.
Please do not open a public issue, pull request or discussion for it.

To encrypt the report, use our GPG key, fingerprint
`111B 1886 A5B8 AD1A 5C94 972D C2D0 B57E 5D97 A563`, published on the
Security page of woohoo-solutions.com. Compare the fingerprint there before
you use it.

Include what you can of: the version (`disconet-collector --version`), the platform
and OS the Collector ran against, what you did, what happened, and what you
expected. Never send a real device's configuration, output or credentials;
a made-up reproduction is enough.

We confirm receipt within 5 working days, keep you told of progress, and
credit you in the release notes unless you ask us not to. We ask that you
give us 90 days to release a fix before you publish.

## In scope

Anything that breaks the read-only rules in the README:

- a command sent to a device that is not in `netstate/commands.yaml` or in
  the fixed session setup the README lists;
- any path into configuration mode;
- a host key accepted without the engineer's explicit `y`, or a changed key
  accepted;
- a secret written to disk unredacted, beyond the limits the README states;
- anything in an export archive besides what the README lists, or a tampered
  archive that `disconet-collector verify` passes;
- anything the Collector sends anywhere other than to the devices in the
  testbed.

## Supported versions

Only the latest release gets fixes.
