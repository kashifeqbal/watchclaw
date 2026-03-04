# Installing WatchClaw

WatchClaw turns a bare Linux server into a hardened, self-defending machine. This guide walks you through installation, verification, upgrading, and removal.

---

## Prerequisites

**Operating System**
- Ubuntu 20.04 / 22.04 / 24.04 ✅
- Debian 11 / 12 ✅
- RHEL / Rocky / Alma Linux 8+ ✅

**Requirements**
- Root access (or `sudo`)
- Python 3.8 or newer
- A public IP address (makes the honeypot useful)
- `curl`, `git`, `systemd`

**Recommended**
- A Telegram bot token for alerts (free, takes 2 minutes via @BotFather)
- At least 1 GB RAM and 2 GB free disk

---

## Quick Install (one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/kashifeqbal/watchclaw/main/install.sh | bash
```

This installs everything with sensible defaults. When it finishes, run `watchclaw status` to verify.

> **Note:** You'll want to configure alerts before calling this production-ready. See [CONFIGURATION.md](CONFIGURATION.md).

---

## Manual Install

If you want to review what's happening, or need to customise before installing:

### 1. Clone the repo

```bash
git clone https://github.com/kashifeqbal/watchclaw.git
cd watchclaw
```

### 2. Configure

```bash
cp config/watchclaw.conf.example config/watchclaw.conf
nano config/watchclaw.conf
```

The most important settings to fill in before running:

```bash
SSH_PORT=2222                          # Where your real SSH will live (not 22)
SSH_ALLOW_USERS="root"                 # Who can SSH in

ALERT_TELEGRAM_TOKEN="your-bot-token" # From @BotFather
ALERT_TELEGRAM_CHAT="-100your-chat-id"
```

See [CONFIGURATION.md](CONFIGURATION.md) for the full options reference.

### 3. Install

```bash
sudo ./install.sh
```

**Available flags:**

| Flag | What it does |
|------|-------------|
| `--standalone` | Default. Pure bash + cron, no extra dependencies |
| `--with-agents` | Also sets up OpenClaw agent integration |
| `--modules=LIST` | Install only specific modules, e.g. `--modules=ssh-harden,ufw-baseline` |
| `--dry-run` | Shows what would happen without actually doing it |
| `--uninstall` | Removes WatchClaw (threat DB is kept) |

### 4. Configure alerts (if you skipped it above)

```bash
nano /etc/watchclaw/watchclaw.conf
```

Add your Telegram token and chat ID, then restart crons:

```bash
# Crons auto-reload — no restart needed. Verify with:
crontab -l
cat /etc/cron.d/watchclaw
```

---

## Selective Module Install

You don't have to install everything. Enable only what you need:

```bash
watchclaw module enable ssh-harden    # SSH hardening
watchclaw module enable ufw-baseline  # Firewall
watchclaw module enable fail2ban      # Brute-force protection
watchclaw module enable cowrie        # SSH honeypot
watchclaw module enable kernel        # Kernel hardening
watchclaw module enable canary        # Tripwire canary tokens
watchclaw module enable threat-feed   # Import/export threat intel
watchclaw module enable sync          # Cross-node threat sharing
```

Or install just a subset upfront:

```bash
sudo ./install.sh --modules=ssh-harden,ufw-baseline,fail2ban
```

---

## Post-Install Verification

After install, run these to confirm everything is working:

```bash
# Security posture summary
watchclaw status

# Run all self-checks
watchclaw selftest

# Check installed modules
watchclaw module list
```

Expected output from `watchclaw status`:

```
SYSTEM HEALTH: OK
SECURITY STATUS: LOW
Risk Meaning: Normal background noise
Action Right Now: No action needed

Active Threat Score (last 30m): 0.0
Top Offender (last 30m): none
Highest Lifetime Offender: none
Repeat Offenders: none
```

**Verify services are running:**

```bash
systemctl status fail2ban
systemctl status cowrie
ufw status
```

**Check crons are scheduled:**

```bash
cat /etc/cron.d/watchclaw
```

---

## Upgrading

```bash
cd /opt/watchclaw
git pull origin main
sudo ./install.sh
```

The installer is idempotent — it's safe to re-run. Your config at `/etc/watchclaw/watchclaw.conf` and your threat database at `/var/lib/watchclaw/` are never overwritten.

---

## Uninstalling

```bash
sudo ./install.sh --uninstall
```

This removes:
- The `watchclaw` CLI from `/usr/local/bin/`
- Cron jobs in `/etc/cron.d/watchclaw`
- The install directory at `/opt/watchclaw/`

This **does not** remove:
- Your config at `/etc/watchclaw/watchclaw.conf`
- Your threat database at `/var/lib/watchclaw/`
- Modules that were installed (cowrie, fail2ban, etc.)

To remove everything including the threat database:

```bash
sudo ./install.sh --uninstall
sudo rm -rf /var/lib/watchclaw /var/log/watchclaw /etc/watchclaw
```

To also remove cowrie:

```bash
systemctl stop cowrie && systemctl disable cowrie
userdel -r cowrie
```

---

## What Gets Installed Where

| Path | What |
|------|------|
| `/opt/watchclaw/` | Scripts, libs, modules |
| `/usr/local/bin/watchclaw` | CLI command |
| `/etc/watchclaw/watchclaw.conf` | Your config |
| `/var/lib/watchclaw/` | Threat database, state, exports |
| `/var/log/watchclaw/` | Logs |
| `/etc/cron.d/watchclaw` | Cron schedules |
| `/etc/sysctl.d/99-watchclaw-hardening.conf` | Kernel settings (kernel module) |
| `/home/cowrie/cowrie/` | Cowrie honeypot (cowrie module) |
