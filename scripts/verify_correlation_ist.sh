#!/usr/bin/env bash
# Verify IST business-window logic (unit checks) and optionally run a full poll against Graylog.
# Usage:
#   ./scripts/verify_correlation_ist.sh              # logic tests only
#   ./scripts/verify_correlation_ist.sh --poll       # also: send auth samples + diy-siem poll (needs stack)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi

echo "=== IST business hours (diy_siem.correlator) ==="
"$PY" <<'PY'
from datetime import datetime, timezone

from diy_siem.correlator import (
    BUSINESS_HOUR_END,
    BUSINESS_HOUR_START,
    BUSINESS_TIMEZONE,
    is_outside_business_hours_ist,
)

# Fixed UTC instants → known IST wall time (no DST in India).
# 2024-06-15 02:30 UTC = 08:00 IST → start of business day (inside [8,18))
inside_morning = datetime(2024, 6, 15, 2, 30, tzinfo=timezone.utc)
# 02:29 UTC = 07:59 IST → before open
before_open = datetime(2024, 6, 15, 2, 29, tzinfo=timezone.utc)
# 12:30 UTC = 18:00 IST → end boundary (outside: hour >= 18)
at_close = datetime(2024, 6, 15, 12, 30, tzinfo=timezone.utc)
# 13:00 UTC = 18:30 IST → night
night = datetime(2024, 6, 15, 13, 0, tzinfo=timezone.utc)

assert BUSINESS_TIMEZONE.key == "Asia/Kolkata"
assert BUSINESS_HOUR_START == 8 and BUSINESS_HOUR_END == 18

assert not is_outside_business_hours_ist(inside_morning), "08:00 IST should be inside business hours"
assert is_outside_business_hours_ist(before_open), "07:59 IST should be outside"
assert is_outside_business_hours_ist(at_close), "18:00 IST should be outside (end is exclusive)"
assert is_outside_business_hours_ist(night), "18:30 IST should be outside"

print(f"Configured window: {BUSINESS_HOUR_START}:00–{BUSINESS_HOUR_END}:00 IST ({BUSINESS_TIMEZONE})")
print("OK: boundary assertions passed.")
PY

if [[ "${1:-}" == "--poll" ]]; then
  echo ""
  echo "=== Integration: send auth samples → poll (needs Graylog + Postgres from docker-compose) ==="
  HOST="${GRAYLOG_SYSLOG_HOST:-127.0.0.1}"
  PORT="${GRAYLOG_SYSLOG_PORT:-5140}"
  bash "$ROOT/scripts/send_auth_sample_syslog.sh" "$HOST" "$PORT" || true
  echo ""
  echo "Running: $PY -m diy_siem poll"
  "$PY" -m diy_siem poll
  echo ""
  echo "Tip: after-hours fires only when success-login messages have timestamps outside 08:00–18:00 IST."
  echo "     Brute-force needs ≥5 failed_login events in the search window (script sends 5)."
fi
