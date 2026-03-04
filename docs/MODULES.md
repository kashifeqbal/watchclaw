# WatchClaw Modules

WatchClaw is built from 8 independent modules. Install all of them or just the ones you need.

```bash
watchclaw module list              # see what's installed
watchclaw module enable <name>     # enable a module
watchclaw module disable <name>    # disable a module
```

---

## ssh-harden

### What it does

Locks down your SSH config. Moves SSH off port 22 (which bots hammer constantly), disables password authentication, and tightens a bunch of sshd settings that most default configs leave wide open.

### What it changes on your system

- Moves SSH to the port you set in `SSH_PORT` (default: 2222)
- Binds SSH to loopback only (`127.0.0.1` and `::1`) — external access via Cloudflare tunnel or reverse proxy
- Disables password authentication (`PasswordAuthentication no`)
- Sets root login to key-only (`PermitRootLogin prohibit-password`)
- Reduces `MaxAuthTries` to 3
- Sets `LoginGraceTime` to 30 seconds
- Backs up your original `sshd_config` to `/etc/ssh/sshd_config.watchclaw-backup`

### Config options

```bash
SSH_PORT=2222              # Port for real SSH (not 22 — that's the honeypot)
SSH_ALLOW_USERS="root"     # Space-separated list of users allowed to SSH
SSH_PUBKEY=""              # Public key to install in authorized_keys (optional)
SSH_DISABLE_PASSWORD=true  # Set false to keep password auth (not recommended)
```

### How to enable/disable

```bash
watchclaw module enable ssh-harden   # applies changes + restarts sshd
watchclaw module disable ssh-harden  # restores backup config
```

### How to verify it's working

```bash
# Check sshd config
grep "^Port" /etc/ssh/sshd_config           # Should show your SSH_PORT
grep "PasswordAuthentication" /etc/ssh/sshd_config  # Should be "no"

# Check it's listening on the right port
ss -tlnp | grep sshd

# Try connecting on the new port
ssh -p 2222 root@localhost
```

> **Before enabling:** Make sure your SSH key is in `~/.ssh/authorized_keys`. You won't be able to use password auth after this.

---

## ufw-baseline

### What it does

Sets up UFW (Uncomplicated Firewall) with sensible defaults. Blocks everything incoming by default, allows the honeypot on port 22, and opens only what you explicitly allow.

### What it changes on your system

- Resets UFW to a clean state
- Sets default policy: deny incoming, allow outgoing
- Allows port 22/tcp (honeypot) — intentionally exposed to attackers
- Blocks external access to your real SSH port (loopback-only)
- Allows any extra ports you specify in `UFW_EXTRA_ALLOW`
- Rate-limits ports in `UFW_RATE_LIMIT_PORTS`
- Enables UFW

### Config options

```bash
UFW_ENABLE=true
UFW_EXTRA_ALLOW="80/tcp 443/tcp"   # Extra ports to open (space-separated)
UFW_RATE_LIMIT_PORTS=""             # Ports to rate-limit (throttle connections)
```

### How to enable/disable

```bash
watchclaw module enable ufw-baseline   # configures and enables UFW
watchclaw module disable ufw-baseline  # runs: ufw --force reset && ufw disable
```

### How to verify it's working

```bash
ufw status verbose

# Should show something like:
# Status: active
# Default: deny (incoming), allow (outgoing)
# 22/tcp  ALLOW IN  Anywhere  # honeypot
# 2222    DENY IN   Anywhere  # blocks external real SSH
```

---

## fail2ban

### What it does

Automatically bans IPs that fail SSH authentication too many times. Works alongside the honeypot — Cowrie handles port 22, fail2ban handles your real SSH port.

### What it changes on your system

- Installs fail2ban if not present
- Creates `/etc/fail2ban/jail.local` with WatchClaw settings
- Enables the `sshd` jail
- Starts and enables the fail2ban service

### Config options

```bash
F2B_ENABLE=true
F2B_BANTIME=-1      # How long to ban (-1 = permanent, 3600 = 1 hour)
F2B_MAXRETRY=3      # Failed attempts before ban
F2B_FINDTIME=600    # Window to count failures in (seconds)
```

### How to enable/disable

```bash
watchclaw module enable fail2ban    # installs + starts fail2ban
watchclaw module disable fail2ban   # systemctl stop fail2ban && systemctl disable fail2ban
```

### How to verify it's working

```bash
systemctl status fail2ban
fail2ban-client status sshd

# Shows:
# - Number of currently banned IPs
# - Total bans
# - List of banned IPs
```

---

## cowrie

### What it does

Installs Cowrie, an SSH honeypot that pretends to be a real SSH server on port 22. When bots and attackers connect and "log in", Cowrie records everything they do — commands run, files downloaded, credentials tried — and WatchClaw scores and bans the attacker.

Any successful honeypot login triggers an instant ban, regardless of score. If a bot logs in, it's banned immediately.

### What it changes on your system

- Creates a `cowrie` system user
- Clones the Cowrie repo to `/home/cowrie/cowrie/`
- Sets up a Python virtualenv for Cowrie
- Configures Cowrie to listen on port 22
- Installs and enables the `cowrie` systemd service

### Config options

```bash
COWRIE_ENABLE=true
COWRIE_USER="cowrie"                # System user Cowrie runs as
COWRIE_DIR="/home/cowrie/cowrie"   # Installation path
```

### How to enable/disable

```bash
watchclaw module enable cowrie     # installs + starts cowrie
watchclaw module disable cowrie    # systemctl stop cowrie && systemctl disable cowrie
```

### How to verify it's working

```bash
systemctl status cowrie

# Check it's listening on port 22
ss -tlnp | grep :22

# Watch live honeypot activity
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log

# Or the JSON log for structured data
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

You should see connection attempts within minutes on any public IP.

---

## kernel

### What it does

Applies a set of sysctl kernel parameters that harden the TCP/IP stack, prevent common network attacks, and reduce information leakage. These are battle-tested settings used in security-hardened production environments.

### What it changes on your system

Writes `/etc/sysctl.d/99-watchclaw-hardening.conf` and applies the settings immediately with `sysctl -p`.

Key settings applied:

| Setting | What it does |
|---------|-------------|
| `tcp_syncookies = 1` | SYN flood protection |
| `rp_filter = 1` | Prevents IP spoofing |
| `accept_redirects = 0` | Blocks ICMP redirect attacks (MITM prevention) |
| `ip_forward = 0` | Server won't act as a router |
| `icmp_echo_ignore_broadcasts = 1` | Smurf attack prevention |
| `log_martians = 1` | Logs packets from impossible source addresses |
| `accept_source_route = 0` | Disables source routing |

### Config options

```bash
KERNEL_HARDEN=true
DISABLE_IPV6=false    # Set true if you don't use IPv6 at all
```

### How to enable/disable

```bash
watchclaw module enable kernel    # writes sysctl config + applies it
watchclaw module disable kernel   # removes the sysctl file + reboots to revert
```

### How to verify it's working

```bash
sysctl net.ipv4.tcp_syncookies    # Should return: 1
sysctl net.ipv4.conf.all.rp_filter  # Should return: 1
cat /etc/sysctl.d/99-watchclaw-hardening.conf
```

---

## canary

### What it does

Creates fake "sensitive" files in places an attacker would look — fake SSH private keys, a Bitcoin wallet, a `.env` with database credentials, AWS credentials. If anything reads or modifies these files, WatchClaw fires an alert.

This catches attackers who've already gotten in and are poking around. It's your last line of defense and the earliest possible warning of a post-compromise situation.

### What it changes on your system

- Creates fake files at the configured `CANARY_PATHS`
- Installs an inotify watcher script (`canary-check.sh`) that monitors those files
- Files contain realistic-looking but completely fake data

### Config options

```bash
CANARY_ENABLE=true
CANARY_PATHS=(
    "/root/.ssh/id_rsa_canary"
    "/etc/shadow.bak"
    "/root/.bitcoin/wallet.dat"
    "/var/www/.env"
    "/root/.aws/credentials_backup"
)
```

You can add any path that makes sense for your server. Think about what an attacker would look for.

### How to enable/disable

```bash
watchclaw module enable canary     # creates canary files + watcher
watchclaw module disable canary    # removes canary files + watcher
```

### How to verify it's working

```bash
# Check canary files exist
ls -la /root/.ssh/id_rsa_canary /etc/shadow.bak

# Trigger a test alert (watch logs for the alert)
cat /root/.ssh/id_rsa_canary
tail -f /var/log/watchclaw/canary.log
```

---

## threat-feed

### What it does

Two things:

**Import:** Pulls known-bad IP lists from public threat intelligence feeds (blocklist.de, AbuseIPDB, stamparm/ipsum, etc.) and pre-emptively bans them via fail2ban.

**Export:** Publishes your own blocklist — the IPs WatchClaw has caught on your server — as a public feed that other WatchClaw users can import.

### What it changes on your system

- Creates `/opt/watchclaw/scripts/watchclaw-import.sh` and `watchclaw-export.sh`
- Creates directories: `/var/lib/watchclaw/feeds/` and `/var/lib/watchclaw/export/`
- If export is enabled and a GitHub repo is configured, can auto-push your blocklist to GitHub Pages

### Config options

```bash
# Import
THREAT_FEEDS=(
    "https://lists.blocklist.de/lists/ssh.txt"
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
)
THREAT_FEED_REFRESH=86400    # How often to refresh (seconds, default: 24h)

# Export
EXPORT_ENABLE=false
EXPORT_FORMAT="json"                         # json, plaintext, or both
EXPORT_PATH="/var/lib/watchclaw/export"     # Where to write export files
EXPORT_GITHUB_REPO=""                        # e.g. "yourname/watchclaw-threats"
EXPORT_MIN_SCORE=25                          # Only export IPs above this score
```

### How to enable/disable

```bash
watchclaw module enable threat-feed    # installs import/export scripts
watchclaw import                       # run an import immediately
watchclaw export                       # run an export immediately
```

### How to verify it's working

```bash
# Check feeds directory after import
ls /var/lib/watchclaw/feeds/

# Check fail2ban picked up the imported IPs
fail2ban-client status sshd | grep "Currently banned"

# Check export output
cat /var/lib/watchclaw/export/blocklist.json
```

---

## sync

### What it does

Shares threat intelligence across a fleet of servers. When one node bans an IP, the others pick it up and pre-emptively ban it too. Uses a shared Git repo as the transport.

Good for: any setup with 2+ servers — VPS fleet, homelab, staging + production.

### What it changes on your system

- Creates `/opt/watchclaw/scripts/watchclaw-sync.sh`
- Creates `/var/lib/watchclaw/sync/` for sync state
- Generates a unique `SYNC_NODE_ID` for this machine
- Adds a cron job (every 15 minutes by default) to push/pull

### Config options

```bash
SYNC_ENABLE=false
SYNC_METHOD="git"              # git (only supported method for now)
SYNC_REPO=""                   # Git repo URL for threat DB sync
SYNC_BRANCH="main"
SYNC_INTERVAL=900              # Sync every 15 minutes
SYNC_NODE_ID=""                # Auto-generated from hostname + machine-id if empty
```

### How to enable/disable

```bash
watchclaw module enable sync      # installs sync script + cron
watchclaw sync push               # push this node's threat intel now
watchclaw sync pull               # pull from shared repo now
watchclaw module disable sync     # removes sync cron
```

### How to verify it's working

```bash
# Manual push/pull
watchclaw sync push
watchclaw sync pull

# Check sync log
tail -f /var/log/watchclaw/sync.log

# Check sync directory
ls /var/lib/watchclaw/sync/
```
