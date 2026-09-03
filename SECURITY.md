# Security policy

## Supported version

Security fixes are provided for the latest `1.x` release. Operators should upgrade to the newest tagged release before reporting a defect.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Send a concise report to `kashifeqbal@hotmail.com` with:

- the affected version or commit;
- the deployment mode and Linux distribution;
- reproduction steps or a minimal proof of concept;
- expected and observed behaviour; and
- any suggested mitigation.

Do not include real credentials, production IP addresses, private threat-feed data or customer logs. Use documentation-only values such as the TEST-NET ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

Receipt should be acknowledged within five business days. Valid reports will be coordinated privately until a fix and release note are available.

## Operational safety

WatchClaw changes SSH, firewall and kernel configuration. Before installation:

1. use a disposable VM or tested backup;
2. keep a second authenticated SSH session open;
3. run `sudo ./install.sh --dry-run`;
4. confirm the chosen SSH port is allowed by the cloud firewall; and
5. verify that console or recovery access is available.

The project reduces common attack surface; it is not a replacement for patch management, least-privilege access, backups or incident response.
