#!/bin/bash
# =============================================================================
# WatchClaw Alert Library — multi-channel alert dispatcher
# =============================================================================

source /etc/watchclaw/watchclaw.conf 2>/dev/null || true

_watchclaw_alert_json() {
    local channel="$1"
    local msg="$2"
    local priority="${3:-normal}"

    python3 - "$channel" "$msg" "$priority" <<'PYEOF'
import datetime
import json
import sys

channel, message, priority = sys.argv[1:4]
if channel == "discord":
    payload = {"content": message}
elif channel == "slack":
    payload = {"text": message}
else:
    payload = {
        "source": "watchclaw",
        "priority": priority,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "message": message,
    }

print(json.dumps(payload, ensure_ascii=False))
PYEOF
}

watchclaw_alert() {
    local msg="$1"
    local priority="${2:-normal}"  # normal, critical

    # Telegram
    if [ -n "${ALERT_TELEGRAM_TOKEN:-}" ] && [ -n "${ALERT_TELEGRAM_CHAT:-}" ]; then
        curl -s --max-time 10 -X POST \
            "https://api.telegram.org/bot${ALERT_TELEGRAM_TOKEN}/sendMessage" \
            -d "chat_id=${ALERT_TELEGRAM_CHAT}" \
            --data-urlencode "text=${msg}" > /dev/null 2>&1
    fi

    # Discord
    if [ -n "${ALERT_DISCORD_WEBHOOK:-}" ]; then
        local json
        json=$(_watchclaw_alert_json "discord" "$msg" "$priority")
        curl -s --max-time 10 -X POST "$ALERT_DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$json" > /dev/null 2>&1
    fi

    # Slack
    if [ -n "${ALERT_SLACK_WEBHOOK:-}" ]; then
        local json
        json=$(_watchclaw_alert_json "slack" "$msg" "$priority")
        curl -s --max-time 10 -X POST "$ALERT_SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$json" > /dev/null 2>&1
    fi

    # Generic webhook
    if [ -n "${ALERT_WEBHOOK_URL:-}" ]; then
        local json
        json=$(_watchclaw_alert_json "webhook" "$msg" "$priority")
        curl -s --max-time 10 -X POST "$ALERT_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            ${ALERT_WEBHOOK_HEADERS:+-H "$ALERT_WEBHOOK_HEADERS"} \
            -d "$json" > /dev/null 2>&1
    fi
}
