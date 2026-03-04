# Contributing to WatchClaw

Pull requests welcome. Here's how to get set up and what we care about.

---

## Development Setup

### 1. Fork and clone

```bash
git clone https://github.com/YOUR_USERNAME/watchclaw.git
cd watchclaw
```

### 2. Install dev tools

```bash
# Bash linting
apt install shellcheck bats

# Or on macOS
brew install shellcheck bats-core
```

### 3. Set up a test environment

WatchClaw installs system services, so it's best to test in a VM or container. A fresh Ubuntu 22.04 VPS or a local VM is ideal.

```bash
# Copy example config
cp config/watchclaw.conf.example config/watchclaw.conf

# Dry run to see what the installer would do
sudo ./install.sh --dry-run
```

---

## Running Tests

```bash
make test     # Run bats test suite
make lint     # bash -n syntax check on all .sh files
make check    # shellcheck (error severity only)
make          # Run all three (lint + check + test)
```

**Individual test files:**

```bash
bats tests/test_install.bats
bats tests/test_modules.bats
bats tests/test_watchclaw_lib.bats
```

**What each does:**
- `make lint` — fast syntax check, catches obvious bash errors
- `make check` — shellcheck with error-severity flags, catches real issues
- `make test` — integration-style tests via bats; some require root or specific services

---

## Project Structure

```
watchclaw/
├── install.sh              # Main installer
├── lib/
│   ├── watchclaw-lib.sh    # Core library: threat DB, scoring, banning, reporting
│   └── watchclaw-alert.sh  # Alert routing (Telegram, Discord, Slack, webhook)
├── modules/
│   ├── ssh-harden/install.sh
│   ├── ufw-baseline/install.sh
│   ├── fail2ban/install.sh
│   ├── cowrie/install.sh
│   ├── kernel/install.sh
│   ├── canary/install.sh
│   ├── threat-feed/install.sh
│   └── sync/install.sh
├── scripts/
│   ├── security-posture.sh         # Main status/report script
│   ├── cowrie-notify.sh            # Reads Cowrie logs → threat DB
│   ├── cowrie-autoban.sh           # Applies bans based on scores
│   ├── canary-check.sh             # Monitors canary files
│   ├── service-healthcheck.sh      # Checks all services are running
│   ├── watchclaw-weekly-report.sh  # Weekly summary
│   └── watchclaw-preflight.sh      # Pre-install checks
├── config/
│   └── watchclaw.conf.example      # Annotated example config
├── tests/
│   ├── helpers.bash                # Shared test utilities
│   ├── test_install.bats
│   ├── test_modules.bats
│   └── test_watchclaw_lib.bats
└── docs/
    ├── INSTALL.md
    ├── MODULES.md
    ├── CONFIGURATION.md
    └── TROUBLESHOOTING.md
```

---

## Adding a New Module

Each module lives in `modules/<name>/install.sh`. Here's the pattern:

```bash
#!/bin/bash
# =============================================================================
# Module: your-module — Short description
# =============================================================================

set -euo pipefail
source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

log()  { echo -e "\033[0;32m[WatchClaw:your-module]\033[0m $*"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $*"; }

# Check if already installed (make install idempotent)
if already_installed; then
    log "Already installed ✅"
    exit 0
fi

# Install
log "Installing your-module..."

# ... your installation logic ...

log "✅ your-module installed"
```

**Rules for modules:**
1. **Idempotent** — running the installer twice should be safe
2. **Source config first** — `source /etc/watchclaw/watchclaw.conf 2>/dev/null || true`
3. **No hard failures on missing optional deps** — warn and continue
4. **Log what you're doing** — use the `log()` helper
5. **Back up before modifying** — especially for system configs like sshd_config
6. Optionally add an `uninstall.sh` in the same directory

**Register your module:** Add it to the `ALL_MODULES` list in `install.sh`.

**Add config options:** Add defaults and documentation to `config/watchclaw.conf.example`.

**Write tests:** Add test cases to `tests/test_modules.bats`.

---

## Code Style

- **Bash only** for scripts (no external interpreters except Python for data processing)
- **Python inline** (`python3 - <<'PYEOF' ... PYEOF`) for JSON manipulation — keep it in the same file, don't add separate Python files
- **`set -euo pipefail`** at the top of every script
- **Atomic writes** for JSON state files — write to `.tmp` then `mv` to final path
- **No external commands** that aren't in a standard Ubuntu/Debian install, unless you install them explicitly
- Prefer `systemctl` over service, prefer `ufw` over iptables directly

---

## PR Guidelines

**What we accept:**
- New modules (open an issue first to discuss)
- Bug fixes for existing modules
- New alert channel integrations
- New threat feed integrations
- Documentation improvements
- Test coverage improvements

**What to include in a PR:**
1. Description of what changed and why
2. Any new config options added to `watchclaw.conf.example` with comments
3. Tests if adding new functionality
4. Update `CHANGELOG.md` with your change under `[Unreleased]`

**What we won't merge:**
- Changes that break the `--standalone` no-dependency promise
- Changes that require cloud services or API keys to function (they must be optional)
- Modules that can't be cleanly enabled/disabled independently

---

## Reporting Bugs

Open an issue at [github.com/kashifeqbal/watchclaw/issues](https://github.com/kashifeqbal/watchclaw/issues).

Include:
- OS and version (`cat /etc/os-release`)
- WatchClaw version (`watchclaw version`)
- What you expected vs. what happened
- Relevant log output (`/var/log/watchclaw/`)
- Output of `watchclaw selftest` if applicable
