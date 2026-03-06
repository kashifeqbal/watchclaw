#!/bin/bash
# =============================================================================
# cowrie-autoban.sh — Cowrie Honeypot: Auto-Ban + Event Parsing + Alerts
# =============================================================================
# Combined script (merged from cowrie-autoban + cowrie-notify):
#   1. Bans IPs exceeding connection threshold via UFW
#   2. Parses new cowrie log events, feeds threat DB with scored events
#   3. Alerts via Telegram for notable activity (bans, logins, commands, malware)
#   4. Blocks repeat honeypot abusers on port 22 via iptables
#   5. Runs score decay + post-batch cluster/geo checks
#
# Designed to run via cron every 4h. No AI/LLM dependency.
# =============================================================================

set -euo pipefail

ENV_FILE="/root/.openclaw/.env"
[ -f "$ENV_FILE" ] && set -a && source "$ENV_FILE" && set +a

LOGFILE="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
BAN_LOG="/root/.openclaw/workspace/agents/ops/logs/cowrie-bans.log"
STATEFILE="/root/.openclaw/workspace/agents/ops/logs/cowrie-lastpos"
THRESHOLD=20
UFW="/usr/sbin/ufw"
IPTABLES="/usr/sbin/iptables"
BOT_TOKEN="${OPS_TELEGRAM_BOT:-}"
CHAT_ID="${ALERTS_TELEGRAM_CHAT:--5206059645}"
BURST_THRESHOLD=5
QUIET_TZ="Asia/Kolkata"

is_quiet_hours() {
    local h
    h=$(TZ="$QUIET_TZ" date +%H)
    [ "$h" -ge 23 ] || [ "$h" -lt 8 ]
}

send_telegram() {
    [ -z "$BOT_TOKEN" ] && return 0
    curl -s --max-time 10 -X POST \
        "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}" \
        --data-urlencode "text=$1" > /dev/null
}

# Source WatchClaw library
LIB_DIR="$(dirname "$0")/lib"
# shellcheck source=scripts/lib/threat-db.sh
source "${LIB_DIR}/threat-db.sh"

mkdir -p "$(dirname "$BAN_LOG")" "$(dirname "$STATEFILE")"

[ ! -f "$LOGFILE" ] && exit 0

argus_init

# =============================================================================
# PHASE 1: Connection-count bans (original autoban logic)
# =============================================================================
BANNED_NEW=""
NEW_BAN_COUNT=0

FLAGGED=$(python3 - <<'PYEOF'
import json
from collections import Counter
import datetime

counter = Counter()
today = datetime.date.today().isoformat()
try:
    with open('/home/cowrie/cowrie/var/log/cowrie/cowrie.json') as f:
        for line in f:
            try:
                e = json.loads(line)
                if e.get('eventid') == 'cowrie.session.connect' and \
                   e.get('timestamp', '').startswith(today):
                    counter[e['src_ip']] += 1
            except Exception:
                pass
except Exception:
    pass

for ip, count in counter.items():
    if count >= 20:
        print(f"{ip}|{count}")
PYEOF
)

for ENTRY in $FLAGGED; do
    IP=$(echo "$ENTRY" | cut -d'|' -f1)
    COUNT=$(echo "$ENTRY" | cut -d'|' -f2)

    EXTRA="bulk_connections_${COUNT}"
    threat_record_event "$IP" "recon_fingerprint" "$EXTRA" > /dev/null 2>&1 || true

    if [ "$COUNT" -ge "$((THRESHOLD * 5))" ]; then
        threat_record_event "$IP" "recon_fingerprint" "high_volume" > /dev/null 2>&1 || true
    fi

    BAN_TYPE=$(threat_check_and_ban "$IP" 2>/dev/null || echo "none")

    if ! $UFW status | grep -q "$IP"; then
        $UFW deny from "$IP" to any comment "cowrie-autoban" 2>/dev/null || true
        TS=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$TS] BANNED: $IP (connections: $COUNT, argus_ban: $BAN_TYPE)" >> "$BAN_LOG"
        NEW_BAN_COUNT=$((NEW_BAN_COUNT + 1))
        BANNED_NEW="${BANNED_NEW}
🚫 ${IP} (${COUNT} connections, score-ban: ${BAN_TYPE})"
    fi
done

# =============================================================================
# PHASE 2: Event parsing + threat DB feeding (merged from cowrie-notify)
# =============================================================================
LASTPOS=0
[ -f "$STATEFILE" ] && LASTPOS=$(cat "$STATEFILE")
FILESIZE=$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)

# Reset if file was rotated
[ "$FILESIZE" -lt "$LASTPOS" ] && LASTPOS=0

NEW_LINES=$(tail -c +"$((LASTPOS + 1))" "$LOGFILE" 2>/dev/null)
echo "$FILESIZE" > "$STATEFILE"

EVENT_BAN_LINES=()
FAILED_SUMMARY=""
CRITICAL_ALERTS=""

if [ -n "$NEW_LINES" ]; then
    # Parse all cowrie events
    _PYSC=$(mktemp /tmp/cowrie-parse-XXXXXX.py)
    cat > "$_PYSC" <<'PYEOF'
import sys, json

scored_events = []

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e  = json.loads(line)
        t  = e.get('eventid', '')
        ip = e.get('src_ip', '?')

        if t == 'cowrie.login.failed':
            scored_events.append((ip, 'failed_login', '', None))

        elif t == 'cowrie.login.success':
            user = e.get('username', '?')
            pw   = e.get('password', '?')
            s    = f"🚨 LOGIN SUCCESS: {ip} user={user} pass={pw}"
            scored_events.append((ip, 'login_success', f"{user}:{pw}", s))

        elif t == 'cowrie.command.input':
            cmd = e.get('input', '?')
            event_type = 'command_exec'
            s = f"💻 Command: {ip} ran: {cmd}"
            if any(k in cmd for k in ('authorized_keys', '.bashrc', '.profile', 'crontab', 'systemctl enable', 'rc.local')):
                event_type = 'persistence_attempt'
                s = f"⛓️ Persistence attempt: {ip} cmd: {cmd}"
            scored_events.append((ip, event_type, cmd, s))

        elif t == 'cowrie.session.file_download':
            url = e.get('url', '?')
            scored_events.append((ip, 'malware_download', url, f"📥 Malware download: {ip} → {url}"))

        elif t == 'cowrie.direct-tcpip.request':
            dst = e.get('dst_ip', '?')
            scored_events.append((ip, 'tunnel_tcpip', dst, f"🌐 Tunnel attempt: {ip} → {dst}"))

        elif t in ('cowrie.fingerprint.ssh', 'cowrie.client.version'):
            scored_events.append((ip, 'recon_fingerprint', t, None))

        elif t == 'cowrie.session.connect':
            scored_events.append((ip, 'failed_login', '', None))

    except Exception:
        pass

for ip, event_type, extra, display in scored_events:
    disp = display if display else ''
    extra_safe = extra.replace('|', '/') if extra else ''
    disp_safe  = disp.replace('\n', ' ')
    print(f"SCORE_EVENT|{ip}|{event_type}|{extra_safe}|{disp_safe}")

# Aggregate failed logins
failed_ips = {}
for ip, event_type, extra, display in scored_events:
    if event_type == 'failed_login':
        failed_ips[ip] = failed_ips.get(ip, 0) + 1

if failed_ips:
    total  = sum(failed_ips.values())
    ip_cnt = len(failed_ips)
    top5   = ', '.join(list(failed_ips.keys())[:5])
    print(f"FAILED_SUMMARY|{total}|{ip_cnt}|{top5}")

# Critical events for safety-net alert
critical = []
for ip, event_type, extra, display in scored_events:
    if event_type == 'login_success':
        critical.append(display)
    elif event_type == 'malware_download':
        critical.append(display)
    elif event_type == 'tunnel_tcpip':
        critical.append(display)
if critical:
    print(f"CRITICAL|{'|'.join(critical[:10])}")
PYEOF
    PARSE_OUTPUT=$(echo "$NEW_LINES" | python3 "$_PYSC" 2>/dev/null)
    rm -f "$_PYSC"

    # Feed events into threat DB
    while IFS='|' read -r record_type f1 f2 f3 f4; do
        case "$record_type" in
            SCORE_EVENT)
                ip="$f1"; event_type="$f2"; extra="$f3"
                new_score=$(threat_record_event "$ip" "$event_type" "$extra" 2>/dev/null || echo 0)
                ban_applied=$(threat_check_and_ban "$ip" 2>/dev/null || echo "none")
                if [ "$ban_applied" != "none" ]; then
                    EVENT_BAN_LINES+=("🚫 Auto-ban ($ban_applied): $ip (score: $new_score)")
                fi
                ;;
            FAILED_SUMMARY)
                total="$f1"; ip_cnt="$f2"; top5="$f3"
                FAILED_SUMMARY="🔒 ${total} login attempts from ${ip_cnt} IPs: ${top5}"
                ;;
            CRITICAL)
                shift_args="${f1}|${f2}|${f3}|${f4}"
                CRITICAL_ALERTS=$(echo "$shift_args" | tr '|' '\n')
                ;;
        esac
    done <<< "$PARSE_OUTPUT"

    # Update rolling baseline
    TOTAL_EVENTS=$(echo "$PARSE_OUTPUT" | grep -c '^SCORE_EVENT' || echo 0)
    threat_update_baseline "$TOTAL_EVENTS"
fi

# =============================================================================
# PHASE 3: Telegram alerts (unified from both scripts)
# =============================================================================
MSG_BODY=""
EVENT_BAN_COUNT=${#EVENT_BAN_LINES[@]}

# Connection-count bans
if [ "$NEW_BAN_COUNT" -gt 0 ]; then
    MSG_BODY="${MSG_BODY}${BANNED_NEW}
"
fi

# Critical alerts (login success, malware, tunnels)
if [ -n "$CRITICAL_ALERTS" ]; then
    MSG_BODY="${MSG_BODY}${CRITICAL_ALERTS}
"
fi

# Failed login summary
if [ -n "$FAILED_SUMMARY" ]; then
    MSG_BODY="${MSG_BODY}${FAILED_SUMMARY}
"
fi

# Score-based bans from event parsing
if [ "$EVENT_BAN_COUNT" -gt 0 ]; then
    for line in "${EVENT_BAN_LINES[@]:0:5}"; do
        MSG_BODY="${MSG_BODY}${line}
"
    done
fi

# Alert policy: quiet hours only send critical/burst alerts
SHOULD_SEND=0
if [ -n "$MSG_BODY" ]; then
    if is_quiet_hours; then
        if [ -n "$CRITICAL_ALERTS" ] || [ "$NEW_BAN_COUNT" -ge "$BURST_THRESHOLD" ] || [ "$EVENT_BAN_COUNT" -ge "$BURST_THRESHOLD" ]; then
            SHOULD_SEND=1
        fi
    else
        SHOULD_SEND=1
    fi
fi

if [ "$SHOULD_SEND" -eq 1 ]; then
    TS_LABEL=$(date '+%H:%M UTC%z')
    TOTAL_BANS=$((NEW_BAN_COUNT + EVENT_BAN_COUNT))
    if [ "$TOTAL_BANS" -ge "$BURST_THRESHOLD" ]; then
        HEADER="🚨 Cowrie Alert — ${TS_LABEL} (${TOTAL_BANS} bans)"
    elif [ "$TOTAL_BANS" -gt 0 ]; then
        HEADER="🛡️ Cowrie Alert — ${TS_LABEL} (${TOTAL_BANS} bans)"
    else
        HEADER="🪤 Cowrie Activity — ${TS_LABEL}"
    fi
    send_telegram "${HEADER}

${MSG_BODY}"
fi

# =============================================================================
# PHASE 4: Maintenance (port-22 blocking, ban verification, decay)
# =============================================================================

# Block repeat honeypot abusers from port 22 via iptables
COWRIE_BLOCKED=$(python3 - "${WATCHCLAW_DB:-${HOME:-/root}/.watchclaw/threat-db.json}" <<'PYEOF' 2>/dev/null
import sys, json
db_path = sys.argv[1]
try:
    with open(db_path) as f: db = json.load(f)
except: db = {}
for ip, rec in db.items():
    et = rec.get('event_types', {})
    if et.get('login_success', 0) >= 5:
        print(ip)
PYEOF
)

COWRIE_BAN_LOG="/root/.openclaw/workspace/agents/ops/logs/cowrie-port22-bans.log"
for ip in $COWRIE_BLOCKED; do
    if ! $IPTABLES -C INPUT -s "$ip" -p tcp --dport 22 -j DROP 2>/dev/null; then
        $IPTABLES -I INPUT 1 -s "$ip" -p tcp --dport 22 -j DROP 2>/dev/null || true
        echo "[$(date -Iseconds)] COWRIE-BLOCKED: $ip (5+ honeypot logins)" >> "$COWRIE_BAN_LOG"
    fi
done

# Verify existing bans are still in UFW
INEFFECTIVE=$(threat_verify_bans 2>/dev/null || true)
if [ -n "$INEFFECTIVE" ]; then
    while IFS='|' read -r bip btype breason; do
        if [ -n "$bip" ]; then
            $UFW deny from "$bip" to any comment "watchclaw-reapplied" 2>/dev/null || true
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] REAPPLIED: $bip ($btype) $breason" >> "$BAN_LOG"
        fi
    done <<< "$INEFFECTIVE"
fi

# Score decay (at most once per hour)
DECAY_LOCKFILE="${WATCHCLAW_DIR:-${HOME:-/root}/.watchclaw}/.decay_last_run"
NOW_TS=$(date +%s)
LAST_DECAY=0
[ -f "$DECAY_LOCKFILE" ] && LAST_DECAY=$(cat "$DECAY_LOCKFILE" 2>/dev/null || echo 0)
if [ $(( NOW_TS - LAST_DECAY )) -gt 3600 ]; then
    watchclaw_decay_all 2>/dev/null || true
    echo "$NOW_TS" > "$DECAY_LOCKFILE"
fi

# Post-batch: cluster detection + geo anomaly checks
watchclaw_post_batch 2>/dev/null || true
