# Configuration Reference

WatchClaw is configured via a single file: `/etc/watchclaw/watchclaw.conf`

Start from the example: `cp config/watchclaw.conf.example /etc/watchclaw/watchclaw.conf`

Everything has a sane default. You only need to set what you actually want to change.

---

## SSH

```bash
SSH_PORT=2222
```
The port your real SSH listens on. Port 22 is taken by the Cowrie honeypot. Pick anything above 1024 that you'll remember. Common choices: 2222, 22000, 22022.

```bash
SSH_ALLOW_USERS="root"
```
Space-separated list of users who are allowed to SSH in. If you have a deploy user or non-root account, add them here: `SSH_ALLOW_USERS="root deploy"`

```bash
SSH_DISABLE_PASSWORD=true
```
Turns off password auth entirely — SSH keys only. Default is `true`. Don't set to `false` unless you have a specific reason.

---

## Cowrie Honeypot

```bash
COWRIE_ENABLE=true
```
Whether to install and run the SSH honeypot on port 22.

```bash
COWRIE_USER="cowrie"
```
The system user Cowrie runs under. Leave this alone unless you have a naming conflict.

```bash
COWRIE_DIR="/home/cowrie/cowrie"
```
Where Cowrie is installed. Only change this if you want it somewhere unusual.

---

## Firewall (UFW)

```bash
UFW_ENABLE=true
```
Whether to configure UFW. If you're managing your firewall yourself, set to `false`.

```bash
UFW_EXTRA_ALLOW=""
```
Ports to open in UFW, space-separated. For a web server: `UFW_EXTRA_ALLOW="80/tcp 443/tcp"`. For multiple: `UFW_EXTRA_ALLOW="80/tcp 443/tcp 8080/tcp"`

```bash
UFW_RATE_LIMIT_PORTS=""
```
Ports to rate-limit (throttle connections to prevent flood). Example: `UFW_RATE_LIMIT_PORTS="22000/tcp"`

---

## Fail2ban

```bash
F2B_ENABLE=true
```
Whether to configure fail2ban.

```bash
F2B_BANTIME=-1
```
How long to ban an IP after hitting the retry limit. `-1` means permanent. `3600` = 1 hour. `86400` = 1 day.

```bash
F2B_MAXRETRY=3
```
Number of failed login attempts before banning. Default is 3 — after 3 failures in the `F2B_FINDTIME` window, the IP is banned.

```bash
F2B_FINDTIME=600
```
The window (in seconds) in which `F2B_MAXRETRY` failures must occur. Default is 600 seconds (10 minutes).

---

## Scoring & Ban Policy

WatchClaw scores every attacker IP based on what they do. Different events add different points. Once a score crosses a threshold, the IP gets banned.

### Score thresholds

```bash
BAN_THRESHOLD_SHORT=25        # Score ≥ 25 → 24-hour ban
BAN_THRESHOLD_LONG=75         # Score ≥ 75 → 7-day ban
BAN_THRESHOLD_PERMANENT=150   # Score ≥ 150 → permanent ban
```

### Instant bans

```bash
HONEYPOT_LOGIN_INSTANT_BAN=true
```
Any successful login on the honeypot (port 22) triggers an immediate ban, regardless of score. If a bot successfully "authenticates" on the honeypot, it's clearly hostile. Default: `true`.

### Severity display thresholds

These control what `watchclaw status` shows as the security level (LOW/ELEVATED/HIGH/CRITICAL). The numbers are the rolling 30-minute threat score.

```bash
SEVERITY_LOW=0          # Below this → LOW
SEVERITY_ELEVATED=100   # 100–299 → ELEVATED
SEVERITY_HIGH=300       # 300–599 → HIGH
SEVERITY_CRITICAL=600   # 600+ (with hard signal) → CRITICAL
```

```bash
CRITICAL_REQUIRES_HARD_SIGNAL=true
```
When `true`, CRITICAL status only triggers if there's an actual serious event (malware download, persistence attempt, tunnel/port-forward, or high-volume command execution) — not just heavy recon. This prevents a bot storm from showing CRITICAL when it's really just noisy scanners. Default: `true`.

### Recon tuning

```bash
RECON_SCORE=3         # Points per recon event
RECON_CAP_30M=30      # Max recon points per IP per 30 minutes
```

Recon events (fingerprinting, scanning) are capped so a single noisy scanner doesn't dominate your score chart. An IP doing pure recon can score at most 30 points in any 30-minute window.

---

## Kernel Hardening

```bash
KERNEL_HARDEN=true
```
Whether to apply sysctl kernel hardening settings.

```bash
DISABLE_IPV6=false
```
Set to `true` if your server doesn't use IPv6 at all. This disables IPv6 at the kernel level, which closes a small attack surface. Check with `ip -6 addr` before enabling — some cloud providers use IPv6 for internal networking.

---

## Canary Tokens

```bash
CANARY_ENABLE=true
```
Whether to create canary tripwire files.

```bash
CANARY_PATHS=(
    "/root/.ssh/id_rsa_canary"
    "/etc/shadow.bak"
    "/root/.bitcoin/wallet.dat"
    "/var/www/.env"
)
```
The fake files to create. Pick paths that an attacker would realistically target on your server. The content is automatically generated to look authentic (fake private keys, fake credentials, etc.).

---

## Alerts

You need at least one alert channel. Telegram is the simplest to set up.

### Telegram

```bash
ALERT_TELEGRAM_TOKEN=""     # Your bot token from @BotFather
ALERT_TELEGRAM_CHAT=""      # Chat ID (use @userinfobot to find yours)
```

To get your chat ID: Message @userinfobot on Telegram. Group chat IDs are negative numbers (e.g. `-1001234567890`).

### Discord

```bash
ALERT_DISCORD_WEBHOOK=""    # Webhook URL from Discord server settings
```

In Discord: Server Settings → Integrations → Webhooks → New Webhook → Copy URL.

### Slack

```bash
ALERT_SLACK_WEBHOOK=""      # Incoming webhook URL from Slack app settings
```

### Generic webhook (any HTTP endpoint)

```bash
ALERT_WEBHOOK_URL=""        # Any URL that accepts POST with JSON
ALERT_WEBHOOK_HEADERS=""    # Extra headers, e.g. "Authorization: Bearer mytoken"
```

### Alert rate limiting

```bash
ALERT_RATE_LIMIT=300        # Minimum seconds between similar alerts (5 minutes)
ALERT_BATCH_INTERVAL=3600   # Batch non-critical alerts, send at most once per hour
```

These prevent alert fatigue. LOW severity events are never alerted — they're silently logged. ELEVATED and above will alert, but at most once per `ALERT_RATE_LIMIT` seconds per severity level.

---

## Threat Feed Import

```bash
THREAT_FEEDS=(
    "https://lists.blocklist.de/lists/ssh.txt"
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
)
```
URLs to pull threat intelligence from. WatchClaw supports plain IP lists (one IP per line, `#` comments ignored) and JSON feeds. Leave empty if you don't want to import external feeds.

```bash
THREAT_FEED_REFRESH=86400   # How often to re-fetch feeds (seconds). Default: 24h
```

---

## Threat Feed Export

```bash
EXPORT_ENABLE=false
```
Whether to publish your own blocklist. Useful if you want to share your threat intelligence with others.

```bash
EXPORT_FORMAT="json"                          # json, plaintext, or both
EXPORT_PATH="/var/lib/watchclaw/export"      # Where to write the export files
EXPORT_GITHUB_REPO=""                         # "yourname/your-threat-repo" to auto-push
EXPORT_GITHUB_BRANCH="main"
EXPORT_MIN_SCORE=25                           # Only export IPs above this score
```

---

## Cross-Node Sync

```bash
SYNC_ENABLE=false
```
Whether to sync threat intelligence with other WatchClaw nodes.

```bash
SYNC_METHOD="git"           # Only "git" is supported currently
SYNC_REPO=""                # Git repo URL for the shared threat database
SYNC_BRANCH="main"
SYNC_INTERVAL=900           # How often to sync (seconds). Default: 15 minutes
SYNC_NODE_ID=""             # Auto-generated from hostname + machine-id if empty
```

To use sync, create a private Git repo and give all your nodes push access. Each node writes its high-confidence bans to the shared repo, and reads bans from all other nodes.

---

## Monitoring Schedule (Cron)

These control when the background tasks run. Defaults are sensible — only change them if you have a specific need.

```bash
CRON_NOTIFY_INTERVAL="*/15 * * * *"      # Process cowrie events every 15 minutes
CRON_AUTOBAN_INTERVAL="*/15 * * * *"     # Enforce auto-bans every 15 minutes
CRON_POSTURE_INTERVAL="*/30 * * * *"     # Security posture check every 30 minutes
CRON_HEALTHCHECK_INTERVAL="*/30 * * * *" # Service health check every 30 minutes
CRON_WEEKLY_REPORT="0 9 * * 1"          # Weekly summary every Monday at 9 AM
CRON_FEED_IMPORT="0 */6 * * *"          # Import threat feeds every 6 hours
CRON_EXPORT="0 */6 * * *"              # Export blocklist every 6 hours
CRON_SYNC="*/15 * * * *"               # Cross-node sync every 15 minutes
```

---

## OpenClaw Integration (optional)

```bash
OPENCLAW_ENABLE=false
OPENCLAW_AGENT_ID="ops"
OPENCLAW_RPC_SOCKET=""        # Path to OpenClaw RPC socket
```

Only needed if you're using WatchClaw alongside an OpenClaw agent. Leave disabled for standalone deployments.

---

## Common Setups

### Minimal — just hardening, no honeypot

```bash
SSH_PORT=2222
SSH_ALLOW_USERS="root"
UFW_ENABLE=true
UFW_EXTRA_ALLOW="80/tcp 443/tcp"
F2B_ENABLE=true
COWRIE_ENABLE=false
KERNEL_HARDEN=true
CANARY_ENABLE=false
ALERT_TELEGRAM_TOKEN="your-token"
ALERT_TELEGRAM_CHAT="-100your-chat-id"
```

### Full setup — everything on, Telegram alerts

```bash
SSH_PORT=2222
UFW_ENABLE=true
UFW_EXTRA_ALLOW="80/tcp 443/tcp"
COWRIE_ENABLE=true
F2B_ENABLE=true
F2B_BANTIME=-1
KERNEL_HARDEN=true
CANARY_ENABLE=true
THREAT_FEEDS=("https://lists.blocklist.de/lists/ssh.txt")
ALERT_TELEGRAM_TOKEN="your-token"
ALERT_TELEGRAM_CHAT="-100your-chat-id"
```

### Fleet setup — sync enabled

Same as full setup, plus:

```bash
SYNC_ENABLE=true
SYNC_REPO="git@github.com:yourname/watchclaw-fleet-threats.git"
SYNC_NODE_ID="vps-prod-01"
EXPORT_ENABLE=true
EXPORT_FORMAT="json"
```
