#!/bin/bash
# =============================================================================
# watchclaw-db-maintenance.sh — Daily threat DB housekeeping
# =============================================================================
# Prunes stale IPs (default: >45 days), decays threat scores, and verifies
# that UFW bans match the threat DB. Designed to run unattended via cron.
# =============================================================================

set -euo pipefail

CONF="${WATCHCLAW_CONF:-/etc/watchclaw/watchclaw.conf}"
[ -f "$CONF" ] && source "$CONF"

# Resolve lib directory (works from /opt/watchclaw or repo checkout)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"
[ -f "${LIB_DIR}/watchclaw-lib.sh" ] || LIB_DIR="${SCRIPT_DIR}/lib"

# shellcheck source=../lib/watchclaw-lib.sh
source "${LIB_DIR}/watchclaw-lib.sh"

TS=$(date '+%Y-%m-%d %H:%M:%S')
echo "[$TS] DB maintenance starting"

watchclaw_init

# 1. Prune old entries (default: 45 days)
echo "[$TS] Pruning stale IPs..."
watchclaw_prune_db

# 2. Decay all threat scores
echo "[$TS] Decaying threat scores..."
watchclaw_decay_all

# 3. Verify UFW bans match threat DB
echo "[$TS] Verifying ban consistency..."
watchclaw_verify_bans 2>/dev/null || true

echo "[$(date '+%Y-%m-%d %H:%M:%S')] DB maintenance complete"
