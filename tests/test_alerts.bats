#!/usr/bin/env bats

setup() {
    export WATCHCLAW_REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
    # shellcheck source=/dev/null
    source "${WATCHCLAW_REPO_ROOT}/lib/watchclaw-alert.sh"
}

@test "Discord JSON preserves quotes and shell-like text" {
    message="scanner said '''; echo pwned; \"quoted\""
    run _watchclaw_alert_json "discord" "$message" "critical"
    [ "$status" -eq 0 ]
    python3 - "$output" "$message" <<'PYEOF'
import json
import sys
assert json.loads(sys.argv[1]) == {"content": sys.argv[2]}
PYEOF
}

@test "Slack JSON preserves multiline Unicode text" {
    message=$'first line\nsecond line — blocked'
    run _watchclaw_alert_json "slack" "$message" "normal"
    [ "$status" -eq 0 ]
    python3 - "$output" "$message" <<'PYEOF'
import json
import sys
assert json.loads(sys.argv[1]) == {"text": sys.argv[2]}
PYEOF
}

@test "Generic webhook JSON includes metadata and exact message" {
    message='honeypot event: $(not-executed)'
    run _watchclaw_alert_json "webhook" "$message" "critical"
    [ "$status" -eq 0 ]
    python3 - "$output" "$message" <<'PYEOF'
import json
import sys
payload = json.loads(sys.argv[1])
assert payload["source"] == "watchclaw"
assert payload["priority"] == "critical"
assert payload["message"] == sys.argv[2]
assert payload["timestamp"].endswith("Z")
PYEOF
}
