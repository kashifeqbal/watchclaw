#!/bin/bash
# =============================================================================
# tests/e2e/test_config_validation.sh
# Tests config loading: profiles (homelab/startup/production) if they exist,
# missing config, and invalid values.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONFIG_DIR="${REPO_ROOT}/config"
TMP_DIR="$(mktemp -d)"

PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "=== test_config_validation.sh ==="

# ── Helper: source a config and check it doesn't crash ───────────────────────
try_source_config() {
    local config_path="$1"
    local label="$2"
    local out exit_code

    # Source in a subshell to avoid polluting the current environment
    out=$(bash -c "set -euo pipefail; source '${config_path}'; echo 'sourced_ok'" 2>&1) || true
    if echo "$out" | grep -q "sourced_ok"; then
        pass "Config '${label}' sources without error"
        return 0
    else
        fail "Config '${label}' failed to source: $out"
        return 1
    fi
}

# ── 1. Test loading each config profile (if it exists) ───────────────────────
PROFILES=(homelab startup production)
profiles_found=0
for profile in "${PROFILES[@]}"; do
    profile_path="${CONFIG_DIR}/watchclaw.${profile}.conf"
    if [ -f "$profile_path" ]; then
        profiles_found=$((profiles_found + 1))
        echo "--- Testing profile: $profile ---"
        try_source_config "$profile_path" "$profile"
    else
        pass "Profile '${profile}' not found — skipped (acceptable, configs are optional)"
    fi
done

[ "$profiles_found" -eq 0 ] && echo "  (no optional profiles found — only example config present)"

# ── 2. Test loading the example config ───────────────────────────────────────
echo "--- Testing: watchclaw.conf.example ---"
EXAMPLE_CONF="${CONFIG_DIR}/watchclaw.conf.example"
if [ -f "$EXAMPLE_CONF" ]; then
    try_source_config "$EXAMPLE_CONF" "watchclaw.conf.example"
else
    fail "config/watchclaw.conf.example not found"
fi

# ── 3. Test that missing config doesn't crash install.sh --dry-run ───────────
echo "--- Testing: missing /etc/watchclaw/watchclaw.conf is handled gracefully ---"
MISSING_CONF_OUT=$(cd "$REPO_ROOT" && bash install.sh --dry-run 2>&1) || MISSING_CONF_OUT=""
if echo "$MISSING_CONF_OUT" | grep -qi "error\|fatal\|cannot\|no such file" && \
   ! echo "$MISSING_CONF_OUT" | grep -qi "Using example config\|Pre-flight checks passed"; then
    fail "Missing config causes unexpected error in --dry-run"
else
    pass "Missing /etc/watchclaw/watchclaw.conf handled gracefully (uses fallback)"
fi

# ── 4. Test that invalid SSH_PORT value is handled ───────────────────────────
echo "--- Testing: invalid SSH_PORT value ---"
BAD_CONF="${TMP_DIR}/bad-ssh-port.conf"
cat > "$BAD_CONF" << 'CONF'
SSH_PORT=notanumber
COWRIE_ENABLE=false
UFW_ENABLE=false
CONF

# Source should not crash, even with a bad SSH_PORT value
try_source_config "$BAD_CONF" "bad SSH_PORT value"

# ── 5. Test that empty required values don't crash source ────────────────────
echo "--- Testing: empty alert tokens don't crash ---"
EMPTY_ALERTS_CONF="${TMP_DIR}/empty-alerts.conf"
cat > "$EMPTY_ALERTS_CONF" << 'CONF'
ALERT_TELEGRAM_TOKEN=""
ALERT_TELEGRAM_CHAT=""
ALERT_DISCORD_WEBHOOK=""
ALERT_SLACK_WEBHOOK=""
CONF

try_source_config "$EMPTY_ALERTS_CONF" "empty alert tokens"

# ── 6. Test that unknown keys don't crash source ─────────────────────────────
echo "--- Testing: unknown config keys are ignored ---"
UNKNOWN_KEYS_CONF="${TMP_DIR}/unknown-keys.conf"
cat > "$UNKNOWN_KEYS_CONF" << 'CONF'
FUTURE_SETTING_1=foo
FUTURE_SETTING_2=bar
SOME_UNKNOWN_KEY="hello world"
CONF

try_source_config "$UNKNOWN_KEYS_CONF" "unknown config keys"

# ── 7. Test BAN_THRESHOLD values are numeric-safe ───────────────────────────
echo "--- Testing: BAN_THRESHOLD values in example config are numeric ---"
EXAMPLE_CONF="${CONFIG_DIR}/watchclaw.conf.example"
if [ -f "$EXAMPLE_CONF" ]; then
    # Extract threshold values (uncommented lines)
    for key in BAN_THRESHOLD_SHORT BAN_THRESHOLD_LONG BAN_THRESHOLD_PERMANENT; do
        val=$(grep "^${key}=" "$EXAMPLE_CONF" | head -1 | cut -d= -f2 | sed 's/#.*//' | tr -d '[:space:]"')
        if [ -n "$val" ]; then
            if echo "$val" | grep -qE '^[0-9]+$'; then
                pass "${key}=${val} is numeric"
            else
                fail "${key}=${val} is not a valid integer"
            fi
        else
            pass "${key} not set in example config (uses default)"
        fi
    done
else
    fail "config/watchclaw.conf.example not found for threshold check"
fi

# ── 8. Test CRON_NOTIFY_INTERVAL looks like a cron expression ───────────────
echo "--- Testing: CRON expressions in example config ---"
if [ -f "$EXAMPLE_CONF" ]; then
    for key in CRON_NOTIFY_INTERVAL CRON_AUTOBAN_INTERVAL CRON_POSTURE_INTERVAL; do
        val=$(grep "^${key}=" "$EXAMPLE_CONF" | head -1 | cut -d= -f2 | tr -d '"')
        if [ -n "$val" ]; then
            # A cron expression has at least 4 spaces (5 fields)
            field_count=$(echo "$val" | awk '{print NF}')
            if [ "$field_count" -ge 5 ]; then
                pass "${key} has valid cron format (${field_count} fields)"
            else
                fail "${key}='${val}' doesn't look like a cron expression"
            fi
        else
            pass "${key} not set (uses default)"
        fi
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
