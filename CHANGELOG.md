# Changelog

All notable changes to WatchClaw will be documented here.

Format: [Semantic Versioning](https://semver.org). Types: `Added`, `Changed`, `Fixed`, `Removed`.

---

## [Unreleased]

---

## [1.0.0] — 2026-03-04

First stable release. Born from running a $14 VPS and refusing to let bots win.

### Added

**Core engine**
- `lib/watchclaw-lib.sh` — threat database, event scoring, ban enforcement, decay, pruning
- Score-based ban policy: score ≥25 → 24h ban, ≥75 → 7d ban, ≥150 → permanent
- Instant ban on any successful honeypot login, regardless of score
- Score decay: 10% per 24 hours — old threats naturally fade
- Threat database pruning: removes IPs unseen for >45 days (permanent bans excluded)
- IP enrichment: ASN resolution, geolocation, AbuseIPDB reputation (all cached 24h)
- ASN cluster detection: alerts when 5+ hostile IPs from the same network block
- Geo anomaly detection: alerts on new-country spikes and 3× baseline volume increases
- Rolling 30-minute threat scoring
- Per-IP recon scoring cap (30 points per IP per 30 minutes — prevents recon storms from inflating scores)
- Double penalty for IPs that reappear during an active ban
- Backward compatibility aliases for scripts using older `argus_*`/`threat_*` function names
- One-time migration from predecessor (argus) threat database

**Modules**
- `ssh-harden` — moves SSH off port 22, key-only auth, loopback binding, hardened sshd settings
- `ufw-baseline` — UFW firewall with deny-all default, honeypot-on-22, rate limiting
- `fail2ban` — brute-force protection with configurable bantime, maxretry, findtime
- `cowrie` — SSH honeypot on port 22 with virtualenv setup and systemd service
- `kernel` — 29 sysctl settings: TCP hardening, SYN flood protection, ICMP redirect blocking, IP spoofing prevention, martian packet logging
- `canary` — tripwire canary tokens in realistic-looking fake files (SSH keys, Bitcoin wallet, .env, AWS credentials)
- `threat-feed` — import from public blocklists (blocklist.de, stamparm/ipsum, feodotracker), export your own blocklist
- `sync` — cross-node threat intelligence sharing via Git repository

**Scripts**
- `security-posture.sh` — plain-English security report with health check, scoring, top offenders, recommended action
- `cowrie-notify.sh` — reads Cowrie JSON logs, feeds events into threat database
- `cowrie-autoban.sh` — enforces ban policy based on current scores
- `canary-check.sh` — inotify-based canary file monitor with alert on access
- `service-healthcheck.sh` — checks fail2ban, cowrie, cloudflared, syncthing, disk usage
- `watchclaw-weekly-report.sh` — weekly security summary
- `watchclaw-preflight.sh` — pre-install environment checks
- `watchclaw-critical-issue.sh` — auto-creates GitHub issue on CRITICAL severity (rate-limited to 1 per 6h)

**Installer**
- `install.sh` — one-command installer with `--standalone`, `--with-agents`, `--modules=`, `--dry-run`, `--uninstall` flags
- Auto-detects Debian/Ubuntu vs RHEL/Rocky/Alma
- Installs `watchclaw` CLI at `/usr/local/bin/watchclaw`
- Writes `/etc/cron.d/watchclaw` with all monitoring schedules

**CLI**
- `watchclaw status` — security posture summary
- `watchclaw report` — full security report
- `watchclaw threats` — active threats with scores
- `watchclaw ban <ip>` — manual ban
- `watchclaw unban <ip>` — remove ban
- `watchclaw export` — export blocklist
- `watchclaw import` — pull threat feeds
- `watchclaw sync push|pull` — cross-node sync
- `watchclaw module list|enable|disable` — module management
- `watchclaw selftest` — full diagnostic check
- `watchclaw version` — show version

**Alerts**
- `lib/watchclaw-alert.sh` — multi-channel alert routing
- Telegram alerts with per-severity rate limiting
- Discord webhook support
- Slack incoming webhook support
- Generic HTTP webhook support (POST JSON)
- Alert batching for non-critical events
- LOW severity suppressed (logged silently, not alerted)
- ELEVATED/HIGH/CRITICAL → immediate alert

**Configuration**
- `config/watchclaw.conf.example` — fully annotated config file
- `config/watchclaw.conf.homelab` — minimal homelab profile
- `config/watchclaw.conf.startup` — full hardening with Slack alerts
- `config/watchclaw.conf.production` — everything enabled, multi-channel, cross-node sync

**Documentation**
- `docs/INSTALL.md` — installation guide
- `docs/MODULES.md` — per-module documentation
- `docs/CONFIGURATION.md` — full config reference
- `docs/TROUBLESHOOTING.md` — common issues and fixes
- `CONTRIBUTING.md` — development setup and PR guidelines
- `README.md` — project overview with real security report output

**Tests**
- `tests/test_install.bats`
- `tests/test_modules.bats`
- `tests/test_watchclaw_lib.bats`
- `tests/helpers.bash`
- `Makefile` with `lint`, `check`, `test` targets
- GitHub Actions CI (`/.github/workflows/ci.yml`)

---

[Unreleased]: https://github.com/kashifeqbal/watchclaw/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/kashifeqbal/watchclaw/releases/tag/v1.0.0
