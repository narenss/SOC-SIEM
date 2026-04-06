#!/usr/bin/env bash
# Send one GELF 1.1 JSON message over TCP to Graylog GELF TCP input (host port 12201).
set -euo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-12201}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# GELF 1.1: newline-terminated JSON (keep payload simple for shell quoting)
printf '%s\n' "{\"version\":\"1.1\",\"host\":\"lab\",\"short_message\":\"diy-siem gelf test ${TS}\",\"level\":6,\"_project\":\"diy-siem\"}" | nc -w2 "${HOST}" "${PORT}"
echo ""
echo "Sent GELF short_message to ${HOST}:${PORT}/tcp"
