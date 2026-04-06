#!/usr/bin/env bash
# Send a RFC3164-style syslog line to Graylog Syslog UDP input (host port 5140).
# Facility: local0 (16). Severity sets the PRI (affects how Graylog classifies the line).
#
# Usage:
#   ./send_test_syslog.sh [host] [port]
#   ./send_test_syslog.sh 127.0.0.1 5140 crit
#   SEND_TEST_SYSLOG_SEVERITY=error SEND_TEST_SYSLOG_MESSAGE="auth failure" ./send_test_syslog.sh
#
# Severities: emerg alert crit err warn notice info debug  (default: info)
set -euo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-5140}"
SEV_KEY="${SEND_TEST_SYSLOG_SEVERITY:-${3:-info}}"
SEV_KEY="$(printf '%s' "${SEV_KEY}" | tr '[:upper:]' '[:lower:]')"

case "${SEV_KEY}" in
  emerg|emergency) SEV=0 ;;
  alert) SEV=1 ;;
  crit|critical) SEV=2 ;;
  err|error) SEV=3 ;;
  warn|warning) SEV=4 ;;
  notice) SEV=5 ;;
  info) SEV=6 ;;
  debug) SEV=7 ;;
  *)
    echo "Unknown severity '${SEV_KEY}'. Use: emerg alert crit err warn notice info debug" >&2
    exit 1
    ;;
esac

# PRI = facility * 8 + severity ; local0 = 16
PRI=$((16 * 8 + SEV))
MSG="${SEND_TEST_SYSLOG_MESSAGE:-diy-siem test: hello from send_test_syslog.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ) [severity=${SEV_KEY}]}"
echo "<${PRI}>${MSG}" | nc -u -w1 "${HOST}" "${PORT}"
echo "Sent PRI=${PRI} (${SEV_KEY}) to ${HOST}:${PORT}/udp: ${MSG}"
