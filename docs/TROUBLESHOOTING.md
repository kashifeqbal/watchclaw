# Troubleshooting

Common issues and how to fix them.

---

## Service won't start

### Cowrie fails to start

```bash
systemctl status cowrie
journalctl -u cowrie -n 50
```

**Port 22 already in use:**
```
ERROR: cannot bind to port 22
```
Something else is listening on port 22 (probably the real sshd). The cowrie module and ssh-harden are meant to work together — ssh-harden must run first to move real SSH off port 22.

Fix:
```bash
# Check what's on port 22
ss -tlnp | grep :22
# If it's sshd, make sure ssh-harden ran successfully
grep "^Port" /etc/ssh/sshd_config  # Should NOT be 22
systemctl restart sshd
systemctl start cowrie
```

**Python/venv issues:**
```
ModuleNotFoundError: No module named 'twisted'
```
Cowrie's virtualenv is broken or incomplete.

Fix:
```bash
cd /home/cowrie/cowrie
sudo -u cowrie bash -c "source cowrie-env/bin/activate && pip install -r requirements.txt"
systemctl restart cowrie
```

---

### fail2ban fails to start

```bash
systemctl status fail2ban
fail2ban-client ping
```

**Missing sshd log:**
fail2ban can't find the auth log.

Fix (Ubuntu/Debian):
```bash
# Check if systemd journal is being used
fail2ban-client status sshd
# If backend = "auto" and logs are missing, set backend explicitly:
echo "backend = systemd" >> /etc/fail2ban/jail.local
systemctl restart fail2ban
```

**Config syntax error:**
```bash
fail2ban-client -t  # test config
```

---

### WatchClaw CLI throws "command not found"

The install didn't complete or `PATH` is wrong.

```bash
ls -la /usr/local/bin/watchclaw   # Should exist and be executable
which watchclaw
```

If the file doesn't exist, re-run the installer:
```bash
sudo ./install.sh
```

---

## Alerts not sending

### No Telegram messages

**Step 1: Check config**
```bash
grep ALERT_TELEGRAM /etc/watchclaw/watchclaw.conf
```
Both `ALERT_TELEGRAM_TOKEN` and `ALERT_TELEGRAM_CHAT` must be set.

**Step 2: Test manually**
```bash
source /etc/watchclaw/watchclaw.conf
curl -s "https://api.telegram.org/bot${ALERT_TELEGRAM_TOKEN}/getMe"
# Should return your bot info
```

If that fails, your token is wrong. Regenerate via @BotFather.

**Step 3: Test sending a message**
```bash
curl -s -X POST "https://api.telegram.org/bot${ALERT_TELEGRAM_TOKEN}/sendMessage" \
  -d "chat_id=${ALERT_TELEGRAM_CHAT}" \
  -d "text=WatchClaw test alert"
```

**Step 4: Check rate limiting**

LOW severity events are intentionally suppressed — no alert is sent. Only ELEVATED and above triggers notifications.

```bash
grep "SUPPRESS\|ALERTED" /var/log/watchclaw/posture.log | tail -20
```

If you see `SUPPRESS: severity=LOW` — that's working correctly.

**Step 5: Check the chat ID format**

Group chat IDs are negative: `-1001234567890`. Personal chat IDs are positive. Use @userinfobot to find yours.

---

### Discord/Slack webhooks not firing

Test the webhook directly:
```bash
source /etc/watchclaw/watchclaw.conf

# Discord
curl -s -X POST "$ALERT_DISCORD_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{"content": "WatchClaw test alert"}'

# Slack
curl -s -X POST "$ALERT_SLACK_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{"text": "WatchClaw test alert"}'
```

---

## False positives

### Legitimate IP getting banned

**Unban it:**
```bash
watchclaw unban <ip>
```

**Find why it was banned:**
```bash
# Check its score and history
watchclaw threats | grep <ip>

# Check threat DB directly
python3 -c "
import json
db = json.load(open('/var/lib/watchclaw/threat-db.json'))
ip = '<ip>'
if ip in db:
    import json
    print(json.dumps(db[ip], indent=2))
"
```

**Whitelist it permanently:**

There's no built-in whitelist yet. Workaround:

```bash
# Add UFW allow rule before the deny rule
ufw insert 1 allow from <ip> to any comment "trusted-whitelist"
```

For fail2ban:
```bash
# Add to jail.local
echo "ignoreip = 127.0.0.1/8 ::1 <your-ip>" >> /etc/fail2ban/jail.local
systemctl reload fail2ban
```

---

### Score too high for normal traffic

If your own monitoring tool, backup agent, or CI runner is being scored:

```bash
# Check what's contributing to a specific IP's score
grep "<ip>" /var/log/watchclaw/watchclaw.log
```

Common causes:
- Backup tool doing rapid connections (looks like recon)
- Uptime monitor failing SSH checks
- Development machine trying passwords (key auth misconfigured)

**Tune recon scoring:**
```bash
# Raise the recon cap if you have lots of legitimate scans
RECON_CAP_30M=60   # Default 30, raise to 60
```

---

## Score too low / threats not being caught

### IP should be banned but isn't

**Check its current score:**
```bash
watchclaw threats
# or
python3 -c "
import json
db = json.load(open('/var/lib/watchclaw/threat-db.json'))
for ip, r in sorted(db.items(), key=lambda x: x[1].get('score',0), reverse=True)[:10]:
    print(f'{ip}: {r.get(\"score\",0):.1f}')
"
```

**Check ban thresholds:**
```bash
grep BAN_THRESHOLD /etc/watchclaw/watchclaw.conf
```

Default thresholds: 25 (24h ban), 75 (7d), 150 (permanent). If an IP has score 20, it's below the 24h ban threshold — it needs a bit more activity.

**Lower thresholds if you're being too lenient:**
```bash
BAN_THRESHOLD_SHORT=15     # Ban earlier
BAN_THRESHOLD_LONG=50
BAN_THRESHOLD_PERMANENT=100
```

**Check cron is running:**
```bash
grep watchclaw /var/log/syslog | tail -20
crontab -l
cat /etc/cron.d/watchclaw
```

---

## Cowrie not catching traffic

### Bots aren't hitting the honeypot

**Check port 22 is publicly accessible:**
```bash
# From a different machine:
nc -zv <your-server-ip> 22

# On the server:
ss -tlnp | grep :22
ufw status | grep "22/tcp"
```

**Check UFW isn't blocking port 22:**
```bash
ufw status verbose
```
Port 22/tcp should show `ALLOW IN  Anywhere`.

**Check Cowrie is actually listening:**
```bash
ss -tlnp | grep cowrie
# or
systemctl status cowrie
```

**Check the honeypot logs:**
```bash
tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.log
```

If the log is empty after a few minutes on a public IP, the issue is network — something is blocking incoming port 22.

---

### Cowrie events aren't being processed by WatchClaw

The `cowrie-notify.sh` script (runs every 15 minutes via cron) reads Cowrie logs and feeds events into WatchClaw's threat database.

```bash
# Run manually to check for errors
bash /opt/watchclaw/scripts/cowrie-notify.sh

# Check for parse errors
tail -50 /var/log/watchclaw/notify.log

# Check threat DB is being updated
ls -la /var/lib/watchclaw/threat-db.json
python3 -c "import json; db=json.load(open('/var/lib/watchclaw/threat-db.json')); print(f'{len(db)} IPs tracked')"
```

---

## Sync not working

### Push/pull failing

```bash
watchclaw sync push
# Check error output

tail -50 /var/log/watchclaw/sync.log
```

**SSH key not set up for the sync repo:**
```bash
# Test SSH access to the repo
ssh -T git@github.com

# If using a deploy key, make sure it has write access
ssh-keygen -t ed25519 -f ~/.ssh/watchclaw-sync -N ""
cat ~/.ssh/watchclaw-sync.pub
# Add this as a deploy key on the repo with write access
```

**SYNC_REPO not configured:**
```bash
grep SYNC_REPO /etc/watchclaw/watchclaw.conf
# Should not be empty
```

**Git isn't installed:**
```bash
which git || apt install git
```

---

## Still stuck?

1. Check the logs: `/var/log/watchclaw/`
2. Run `watchclaw selftest` for a diagnostic sweep
3. Check `journalctl -u cowrie` and `journalctl -u fail2ban` for service issues
4. Open an issue: [github.com/kashifeqbal/watchclaw/issues](https://github.com/kashifeqbal/watchclaw/issues)
