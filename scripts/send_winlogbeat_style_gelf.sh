#!/usr/bin/env bash
# GELF TCP samples that mimic Winlogbeat-style metadata for search/dashboard demos.
# short_message includes diy-siem and EventID= for the Syslog-style regex extractor when
# re-ingested; GELF additional fields (_win_event_id, _event) map to Graylog fields for queries.
# Requires GELF TCP input on port 12201 (scripts/bootstrap_inputs.sh).
# Usage: ./scripts/send_winlogbeat_style_gelf.sh [host] [port]
set -euo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-12201}"
TS1="$(date +%s)"
TS2="$((TS1 + 1))"

send_json() {
  printf '%s\n' "$1" | nc -w2 "${HOST}" "${PORT}"
  echo "Sent GELF line to ${HOST}:${PORT}/tcp"
}

send_json "{\"version\":\"1.1\",\"host\":\"win-dc01\",\"short_message\":\"diy-siem gelf EventID=4625 An account failed to log on\",\"timestamp\":${TS1},\"level\":4,\"_event\":\"failed_login\",\"_win_event_id\":4625,\"_user\":\"CONTOSO\\\\backup_svc\",\"_src_ip\":\"203.0.113.88\"}"
send_json "{\"version\":\"1.1\",\"host\":\"win-dc01\",\"short_message\":\"diy-siem gelf EventID=4624 An account was successfully logged on\",\"timestamp\":${TS2},\"level\":6,\"_event\":\"success_login\",\"_win_event_id\":4624,\"_user\":\"CONTOSO\\\\backup_svc\",\"_src_ip\":\"203.0.113.88\"}"
