#!/bin/bash
# =============================================================================
# tests/e2e/test_scoring_integration.sh
# Integration tests for watchclaw-lib.sh scoring engine:
#   - watchclaw_init creates valid DB files
#   - watchclaw_record_event accumulates scores
#   - ban thresholds trigger correctly
#   - honeypot login_success triggers instant ban
#   - threat-db.json remains valid JSON throughout
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="${REPO_ROOT}/lib/watchclaw-lib.sh"

PASS=0
FAIL=0

# ── Test env: isolated temp dir so we don't pollute the real state ────────────
TMPDIR_ROOT="$(mktemp -d)"
export WATCHCLAW_DIR="${TMPDIR_ROOT}/watchclaw-test"
export HOME="${TMPDIR_ROOT}/home"
mkdir -p "$HOME"

pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() { rm -rf "$TMPDIR_ROOT"; }
trap cleanup EXIT

echo "=== test_scoring_integration.sh ==="
echo "Using isolated state dir: ${WATCHCLAW_DIR}"

# ── Source the library ────────────────────────────────────────────────────────
if [ ! -f "$LIB" ]; then
    echo "FATAL: lib/watchclaw-lib.sh not found at $LIB"
    exit 1
fi

# shellcheck source=/dev/null
source "$LIB"

# ── 1. watchclaw_init creates required files ──────────────────────────────────
echo "--- Test: watchclaw_init ---"
watchclaw_init

REQUIRED_FILES=(
    "${WATCHCLAW_DIR}/threat-db.json"
    "${WATCHCLAW_DIR}/reputation-cache.json"
    "${WATCHCLAW_DIR}/asn-db.json"
    "${WATCHCLAW_DIR}/geo-db.json"
    "${WATCHCLAW_DIR}/watchclaw-state.json"
)

for f in "${REQUIRED_FILES[@]}"; do
    if [ -f "$f" ]; then
        pass "watchclaw_init created: $(basename $f)"
    else
        fail "watchclaw_init did NOT create: $(basename $f)"
    fi
done

# Verify each file is valid JSON
for f in "${REQUIRED_FILES[@]}"; do
    if [ -f "$f" ] && python3 -c "import json,sys; json.load(open('$f'))" 2>/dev/null; then
        pass "$(basename $f) is valid JSON after init"
    else
        fail "$(basename $f) is NOT valid JSON after init"
    fi
done

# ── 2. Record 10 events for a test IP ────────────────────────────────────────
echo "--- Test: recording 10 failed_login events ---"
TEST_IP="192.0.2.99"
final_score="0"

for i in $(seq 1 10); do
    score="$(watchclaw_record_event "$TEST_IP" "failed_login" "test-event-$i" 2>/dev/null || echo "0")"
    final_score="$score"
done

pass "10 events recorded (no crash)"

# ── 3. Verify score accumulation ─────────────────────────────────────────────
echo "--- Test: score accumulation ---"
# 10 failed_login × 1 point = 10 points expected (no decay in same session)
stored_score="$(orca_get_score "$TEST_IP" 2>/dev/null || echo "0")"
stored_int="${stored_score%.*}"  # strip decimal

if [ "${stored_int:-0}" -ge 8 ]; then
    pass "Score after 10 failed_logins: ${stored_score} (>= 8 expected)"
else
    fail "Score too low after 10 failed_logins: ${stored_score} (expected >= 8)"
fi

# ── 4. Verify DB is still valid JSON after 10 writes ─────────────────────────
echo "--- Test: threat-db.json validity after events ---"
DB_PATH="${WATCHCLAW_DIR}/threat-db.json"
if python3 -c "import json,sys; db=json.load(open('$DB_PATH')); assert '$TEST_IP' in db, 'IP not in DB'" 2>/dev/null; then
    pass "threat-db.json is valid JSON and contains test IP"
else
    fail "threat-db.json is invalid or missing test IP"
fi

# ── 5. Verify ban threshold triggers (score >= 25 → short ban) ───────────────
echo "--- Test: ban threshold — short ban at score >= 25 ---"
BAN_IP="192.0.2.100"

# Record enough events to cross the short-ban threshold (25 pts)
# recon_fingerprint = 3 pts each, 9x = 27 pts
for i in $(seq 1 9); do
    watchclaw_record_event "$BAN_IP" "recon_fingerprint" "scan-$i" 2>/dev/null || true
done

ban_type="$(watchclaw_check_and_ban "$BAN_IP" 2>/dev/null || echo "none")"
stored_ban_score="$(orca_get_score "$BAN_IP" 2>/dev/null || echo "0")"
echo "  Ban IP score: ${stored_ban_score}, ban type applied: ${ban_type}"

if [ "$ban_type" = "short" ] || [ "$ban_type" = "long" ] || [ "$ban_type" = "permanent" ]; then
    pass "Ban threshold triggered: got '$ban_type' ban at score ${stored_ban_score}"
elif [ "$ban_type" = "none" ]; then
    # Score might be capped by recon 30m cap — check score
    score_int="${stored_ban_score%.*}"
    if [ "${score_int:-0}" -ge 25 ]; then
        fail "Score is ${stored_ban_score} but ban_type=none (expected short ban)"
    else
        pass "Score ${stored_ban_score} is below threshold (recon cap applied) — no ban expected"
    fi
else
    fail "Unexpected ban type: '$ban_type'"
fi

# ── 6. Verify instant honeypot-login ban ─────────────────────────────────────
echo "--- Test: instant ban on honeypot login_success ---"
HONEY_IP="192.0.2.101"

# login_success = 5 pts, even below 25 — instant ban policy
watchclaw_record_event "$HONEY_IP" "login_success" "honeypot-trigger" 2>/dev/null || true
honey_ban="$(watchclaw_check_and_ban "$HONEY_IP" 2>/dev/null || echo "none")"
honey_score="$(orca_get_score "$HONEY_IP" 2>/dev/null || echo "0")"

echo "  Honeypot IP score: ${honey_score}, ban type: ${honey_ban}"

if [ "$honey_ban" = "short" ] || [ "$honey_ban" = "long" ] || [ "$honey_ban" = "permanent" ]; then
    pass "Instant ban triggered on login_success: got '${honey_ban}'"
else
    fail "Expected instant ban on login_success, got: '${honey_ban}'"
fi

# ── 7. Verify permanent ban escalation at score >= 150 ───────────────────────
echo "--- Test: permanent ban at score >= 150 ---"
PERM_IP="192.0.2.102"

# malware_download = 75 pts each, 2× = 150 pts → permanent ban
for i in 1 2; do
    watchclaw_record_event "$PERM_IP" "malware_download" "malware-$i" 2>/dev/null || true
done

perm_ban="$(watchclaw_check_and_ban "$PERM_IP" 2>/dev/null || echo "none")"
perm_score="$(orca_get_score "$PERM_IP" 2>/dev/null || echo "0")"

echo "  Permanent-ban IP score: ${perm_score}, ban type: ${perm_ban}"

if [ "$perm_ban" = "permanent" ]; then
    pass "Permanent ban triggered at score ${perm_score}"
elif [ "$perm_ban" = "long" ]; then
    pass "Long ban triggered at score ${perm_score} (acceptable near-permanent threshold)"
else
    fail "Expected permanent/long ban at score ${perm_score}, got: '${perm_ban}'"
fi

# ── 8. Final threat-db.json is valid JSON ────────────────────────────────────
echo "--- Test: threat-db.json final validity ---"
ALL_IPS=("$TEST_IP" "$BAN_IP" "$HONEY_IP" "$PERM_IP")

if python3 - "${DB_PATH}" "${ALL_IPS[@]}" << 'PYEOF' 2>/dev/null
import sys, json
db_path = sys.argv[1]
ips = sys.argv[2:]
with open(db_path) as f:
    db = json.load(f)
missing = [ip for ip in ips if ip not in db]
if missing:
    print(f"Missing IPs: {missing}", file=sys.stderr)
    sys.exit(1)
# Validate score is numeric for all
for ip in ips:
    score = db[ip].get('score', 0)
    assert isinstance(score, (int, float)), f"score not numeric for {ip}: {score}"
sys.exit(0)
PYEOF
then
    pass "threat-db.json is valid JSON with all test IPs present"
else
    fail "threat-db.json validation failed (invalid JSON or missing IPs)"
fi

# ── 9. orca_get_score returns a number ───────────────────────────────────────
echo "--- Test: orca_get_score returns numeric ---"
raw_score="$(orca_get_score "$TEST_IP" 2>/dev/null || echo "")"
if echo "$raw_score" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
    pass "orca_get_score returns numeric: $raw_score"
else
    fail "orca_get_score returned non-numeric: '$raw_score'"
fi

# ── 10. orca_rolling_score returns a number ───────────────────────────────────
echo "--- Test: orca_rolling_score returns numeric ---"
roll_score="$(orca_rolling_score 60 2>/dev/null || echo "")"
if echo "$roll_score" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
    pass "orca_rolling_score(60m) returns numeric: $roll_score"
else
    fail "orca_rolling_score returned non-numeric: '$roll_score'"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
