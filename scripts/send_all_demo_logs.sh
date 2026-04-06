#!/usr/bin/env bash
# Send all realistic demo batches (syslog + GELF) for a SOC-style walkthrough.
# Prerequisites: docker compose up; ./scripts/bootstrap_inputs.sh; python -m diy_siem graylog-bootstrap
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

echo "=== DIY-SIEM demo log bundle ==="
./scripts/send_test_syslog.sh
./scripts/send_realistic_linux_sshd.sh
./scripts/send_realistic_apache_nginx.sh
./scripts/send_realistic_windows_events.sh
./scripts/send_auth_sample_syslog.sh
./scripts/send_winlogbeat_style_gelf.sh
echo ""
echo "Open Graylog Search: query 'diy-siem' (last 5 minutes). Streams: DIY-SIEM Lab, Authentication, Web."
