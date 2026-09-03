# WatchClaw v1.0 release validation

This document defines what the v1.0 tag means and what it does not mean.

## Release gates

| Gate | Automated check | v1.0 expectation |
|---|---|---|
| Shell syntax | `bash -n` across `lib/`, `scripts/` and `modules/` | Pass |
| Static analysis | ShellCheck errors fail CI | Pass |
| Threat engine | Bats tests for scoring, decay, rolling windows and bans | Pass |
| Installer and modules | Bats structural and argument tests | Pass |
| Alert serialization | Adversarial quotes, multiline text and Unicode round-trip through JSON | Pass |
| CLI and dry run | Ubuntu 24.04 Docker E2E suite | Pass |
| Documentation | Install, configuration, modules, troubleshooting and security guidance | Present |

The authoritative result is the `CI` workflow on the tagged commit. A release must not be published if any required job is red.

## Supported boundary

- Automated E2E validation runs on Ubuntu 24.04.
- Debian/Ubuntu and RHEL-family module paths are implemented, but operators should validate non-Ubuntu distributions in a disposable environment before rollout.
- WatchClaw requires root because it configures SSH, UFW, fail2ban, services and sysctl settings.
- External reputation, alert and feed integrations depend on third-party availability and the operator's credentials.
- Cross-node synchronization is opt-in and the operator owns access control for the backing repository or endpoint.

## Deliberately outside v1.0

- a web dashboard;
- an OpenClaw agent module;
- an Ansible distribution path;
- ARM-specific validation;
- CrowdSec or Wazuh adapters; and
- generated PDF reporting.

These are roadmap items, not implied v1.0 capabilities.
