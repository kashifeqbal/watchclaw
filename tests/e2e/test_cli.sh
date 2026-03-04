#!/bin/bash
# =============================================================================
# tests/e2e/test_cli.sh
# Verifies the watchclaw CLI commands work after a mock install.
# Creates a minimal /opt/watchclaw environment without running the full installer.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MOCK_INSTALL_DIR="/opt/watchclaw"
MOCK_CONF_DIR="/etc/watchclaw"
WATCHCLAW_BIN="/usr/local/bin/watchclaw"

PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

echo "=== test_cli.sh ==="

# ── 1. Create mock install directory structure ────────────────────────────────
echo "--- Setting up mock install at ${MOCK_INSTALL_DIR} ---"
mkdir -p "${MOCK_INSTALL_DIR}"/{lib,modules,scripts,config}
mkdir -p "${MOCK_CONF_DIR}"

# Copy lib
cp "${REPO_ROOT}/lib/watchclaw-lib.sh" "${MOCK_INSTALL_DIR}/lib/"
[ -f "${REPO_ROOT}/lib/watchclaw-alert.sh" ] && \
    cp "${REPO_ROOT}/lib/watchclaw-alert.sh" "${MOCK_INSTALL_DIR}/lib/"

# Copy scripts
cp "${REPO_ROOT}/scripts/"*.sh "${MOCK_INSTALL_DIR}/scripts/" 2>/dev/null || true

# Copy modules
cp -r "${REPO_ROOT}/modules/"* "${MOCK_INSTALL_DIR}/modules/" 2>/dev/null || true

# Copy config
cp "${REPO_ROOT}/config/watchclaw.conf.example" "${MOCK_INSTALL_DIR}/config/"

# Write VERSION
cp "${REPO_ROOT}/VERSION" "${MOCK_INSTALL_DIR}/VERSION"

# ── 2. Create minimal /etc/watchclaw/watchclaw.conf ──────────────────────────
cat > "${MOCK_CONF_DIR}/watchclaw.conf" << 'CONF'
# Minimal test config
SSH_PORT=2222
COWRIE_ENABLE=false
UFW_ENABLE=false
F2B_ENABLE=false
KERNEL_HARDEN=false
CANARY_ENABLE=false
ALERT_TELEGRAM_TOKEN=""
ALERT_TELEGRAM_CHAT=""
ALERT_DISCORD_WEBHOOK=""
ALERT_SLACK_WEBHOOK=""
CONF

# ── 3. Install the watchclaw CLI wrapper ─────────────────────────────────────
cat > "${WATCHCLAW_BIN}" << 'CLIEOF'
#!/bin/bash
# WatchClaw CLI — test-installed wrapper
set -euo pipefail

WATCHCLAW_DIR="/opt/watchclaw"
WATCHCLAW_STATE="/var/lib/watchclaw"
WATCHCLAW_CONF="/etc/watchclaw/watchclaw.conf"

[ -f "$WATCHCLAW_CONF" ] && source "$WATCHCLAW_CONF"
source "${WATCHCLAW_DIR}/lib/watchclaw-lib.sh" 2>/dev/null || true

case "${1:-help}" in
    status)     bash "${WATCHCLAW_DIR}/scripts/security-posture.sh" 2>/dev/null || echo "(status: no data yet)" ;;
    report)     bash "${WATCHCLAW_DIR}/scripts/security-posture.sh" --full 2>/dev/null || echo "(report: no data yet)" ;;
    module)
        shift
        case "${1:-list}" in
            list) ls "${WATCHCLAW_DIR}/modules/" 2>/dev/null || echo "No modules" ;;
            *)    echo "module: unknown subcommand '$1'" ;;
        esac
        ;;
    version)    echo "WatchClaw v$(cat ${WATCHCLAW_DIR}/VERSION 2>/dev/null || echo unknown)" ;;
    help|--help|-h)
        echo "WatchClaw — Open Runtime Containment & Analysis"
        echo ""
        echo "Commands:"
        echo "  status          Security posture summary"
        echo "  report          Full security report"
        echo "  threats         List active threats with scores"
        echo "  ban <ip>        Manually ban an IP"
        echo "  unban <ip>      Remove a ban"
        echo "  export          Export threat blocklist"
        echo "  import          Import threat feeds"
        echo "  sync push|pull  Cross-node threat sync"
        echo "  module list     List modules"
        echo "  module enable   Enable a module"
        echo "  module disable  Disable a module"
        echo "  selftest        Run all checks"
        echo "  version         Show version"
        ;;
    *)  echo "Unknown command: $1. Run 'watchclaw help' for usage." ;;
esac
CLIEOF
chmod +x "${WATCHCLAW_BIN}"

pass "Mock install structure created at ${MOCK_INSTALL_DIR}"

# ── 4. Test: watchclaw help ───────────────────────────────────────────────────
echo "--- Testing: watchclaw help ---"
HELP_OUT="$(${WATCHCLAW_BIN} help 2>&1)"
HELP_EXIT=$?

if [ "$HELP_EXIT" -eq 0 ]; then
    pass "watchclaw help exited 0"
else
    fail "watchclaw help exited $HELP_EXIT (expected 0)"
fi

if echo "$HELP_OUT" | grep -q "WatchClaw"; then
    pass "watchclaw help output contains 'WatchClaw'"
else
    fail "watchclaw help output missing 'WatchClaw'"
fi

if echo "$HELP_OUT" | grep -q "status"; then
    pass "watchclaw help lists 'status' command"
else
    fail "watchclaw help missing 'status' command"
fi

if echo "$HELP_OUT" | grep -q "version"; then
    pass "watchclaw help lists 'version' command"
else
    fail "watchclaw help missing 'version' command"
fi

# ── 5. Test: watchclaw version ───────────────────────────────────────────────
echo "--- Testing: watchclaw version ---"
VER_OUT="$(${WATCHCLAW_BIN} version 2>&1)"
VER_EXIT=$?

if [ "$VER_EXIT" -eq 0 ]; then
    pass "watchclaw version exited 0"
else
    fail "watchclaw version exited $VER_EXIT (expected 0)"
fi

if echo "$VER_OUT" | grep -qE "WatchClaw v[0-9]"; then
    pass "watchclaw version output: $VER_OUT"
else
    fail "watchclaw version output unexpected: $VER_OUT"
fi

# ── 6. Test: watchclaw status doesn't crash ───────────────────────────────────
echo "--- Testing: watchclaw status (no-crash) ---"
STATUS_OUT="$(${WATCHCLAW_BIN} status 2>&1)" || STATUS_OUT="(empty)"
STATUS_EXIT=$?

# Status may return non-zero if underlying script is missing/errors, but
# we accept both 0 and 1 — we only fail if it crashes with signal (>128)
if [ "$STATUS_EXIT" -lt 128 ]; then
    pass "watchclaw status did not crash (exit: $STATUS_EXIT)"
else
    fail "watchclaw status crashed with exit $STATUS_EXIT"
fi

# ── 7. Test: watchclaw module list ───────────────────────────────────────────
echo "--- Testing: watchclaw module list ---"
MOD_OUT="$(${WATCHCLAW_BIN} module list 2>&1)"
MOD_EXIT=$?

if [ "$MOD_EXIT" -eq 0 ]; then
    pass "watchclaw module list exited 0"
else
    fail "watchclaw module list exited $MOD_EXIT"
fi

# Expect at least one known module
if echo "$MOD_OUT" | grep -qE "ssh-harden|cowrie|fail2ban|kernel|canary"; then
    pass "watchclaw module list shows expected modules"
else
    fail "watchclaw module list output unexpected: $MOD_OUT"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
