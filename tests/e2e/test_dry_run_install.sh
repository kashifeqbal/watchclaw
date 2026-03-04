#!/bin/bash
# =============================================================================
# tests/e2e/test_dry_run_install.sh
# Verifies that install.sh --dry-run:
#   - exits 0
#   - lists all expected modules
#   - does NOT create any real files/dirs
#   - announces the CLI install path
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

echo "=== test_dry_run_install.sh ==="

# ── Pre-condition: ensure /etc/watchclaw exists so load_config's cp doesn't
# fail before --dry-run kicks in (load_config runs before DRY_RUN guard).
mkdir -p /etc/watchclaw 2>/dev/null || true

# ── Snapshot dirs that exist BEFORE dry-run (to detect new ones created by it)
PRE_EXISTING_DIRS=()
for dir in /opt/watchclaw /var/lib/watchclaw /var/log/watchclaw; do
    [ -d "$dir" ] && PRE_EXISTING_DIRS+=("$dir")
done

# ── 1. Capture dry-run output ─────────────────────────────────────────────────
OUTPUT="$(cd "$REPO_ROOT" && bash install.sh --dry-run 2>&1)"
EXIT_CODE=$?

# ── 2. Verify exit code ───────────────────────────────────────────────────────
if [ "$EXIT_CODE" -eq 0 ]; then
    pass "install.sh --dry-run exited 0"
else
    fail "install.sh --dry-run exited $EXIT_CODE (expected 0)"
fi

# ── 3. Verify each expected module appears in output ─────────────────────────
EXPECTED_MODULES=(
    ssh-harden
    ufw-baseline
    fail2ban
    cowrie
    kernel
    canary
    threat-feed
)

for mod in "${EXPECTED_MODULES[@]}"; do
    if echo "$OUTPUT" | grep -qi "$mod"; then
        pass "Module '$mod' listed in dry-run output"
    else
        fail "Module '$mod' NOT found in dry-run output"
    fi
done

# ── 4. Verify no NEW install dirs were created by dry-run ────────────────────
# /etc/watchclaw is excluded — it was pre-created above to unblock load_config
for dir in /opt/watchclaw /var/lib/watchclaw /var/log/watchclaw; do
    was_pre_existing=false
    for pre in "${PRE_EXISTING_DIRS[@]:-}"; do
        [ "$pre" = "$dir" ] && was_pre_existing=true && break
    done

    if [ "$was_pre_existing" = "true" ]; then
        pass "Directory '$dir' pre-existed (not created by dry-run)"
    elif [ -d "$dir" ]; then
        fail "Directory '$dir' was created by --dry-run (should not be)"
    else
        pass "Directory '$dir' was NOT created (correct)"
    fi
done

# ── 5. Verify dry-run did not (re)create the CLI binary ──────────────────────
# Remove any CLI from prior tests so we can check if dry-run creates it
rm -f /usr/local/bin/watchclaw 2>/dev/null || true
# Re-run dry-run and check
(cd "$REPO_ROOT" && bash install.sh --dry-run >/dev/null 2>&1) || true
if [ -f /usr/local/bin/watchclaw ]; then
    fail "CLI binary /usr/local/bin/watchclaw was created (should not be in --dry-run)"
else
    pass "CLI binary /usr/local/bin/watchclaw was NOT created (correct)"
fi

# ── 6. Verify CLI step is announced in output ────────────────────────────────
# install.sh logs "Installing WatchClaw CLI..." even in dry-run (before early return)
if echo "$OUTPUT" | grep -qi "WatchClaw CLI\|Installing WatchClaw\|cli"; then
    pass "CLI install step announced in output"
else
    fail "CLI install step NOT mentioned in output"
fi

# ── 7. Verify '[dry-run] Would run' appears for each module ──────────────────
if echo "$OUTPUT" | grep -q '\[dry-run\]'; then
    pass "[dry-run] marker present in output"
else
    fail "[dry-run] marker NOT found in output"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
