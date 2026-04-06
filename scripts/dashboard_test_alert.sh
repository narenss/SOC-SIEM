#!/usr/bin/env bash
# Create REAL alerts in Postgres so they appear on the Flask dashboard.
#
# This is NOT the unit-test suite (see scripts/test_correlation_rules.sh — that uses mocks only).
#
# Prerequisites (typical docker-compose stack):
#   - Graylog reachable at GRAYLOG_API_URL (default http://127.0.0.1:9000)
#   - Syslog UDP input on GRAYLOG_SYSLOG_HOST:GRAYLOG_SYSLOG_PORT (default 127.0.0.1:5140)
#   - Postgres + DATABASE_URL / POSTGRES_* in .env so `diy-siem poll` can insert alerts
#
# Usage:
#   ./scripts/dashboard_test_alert.sh
#
# Then open the dashboard (run `python -m diy_siem serve` in another terminal if needed):
#   http://127.0.0.1:5000/   (override with FLASK_HOST / FLASK_PORT in .env)
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

HOST="${GRAYLOG_SYSLOG_HOST:-127.0.0.1}"
PORT="${GRAYLOG_SYSLOG_PORT:-5140}"

echo "=== Dashboard test alert (live Graylog → Postgres) ==="
echo "Sending syslog samples to ${HOST}:${PORT}/udp ..."
bash "$ROOT/scripts/send_auth_sample_syslog.sh" "$HOST" "$PORT"

echo ""
echo "Waiting 3s for Graylog to index (adjust if your poll returns no matches) ..."
sleep 3

echo ""
echo "Running correlator (inserts alerts) ..."
"$PY" -m diy_siem poll

echo ""
echo "Expected on dashboard after refresh:"
echo "  - auth_brute_force:... (≥5 failed logins in window)"
echo "  - demo_diy_siem_marker (any line containing 'diy-siem')"
echo "  - after_hours_login:... only if success-login timestamps fall outside 08:00–18:00 IST"
echo ""
echo "If poll shows deduplicated and no new row: wait ~10 minutes (dedup window) or clear recent alerts in Postgres."
echo "Dashboard URL: http://${FLASK_HOST:-127.0.0.1}:${FLASK_PORT:-5000}/"
echo "Start UI:      $PY -m diy_siem serve"
