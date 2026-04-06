#!/usr/bin/env bash
# Send RFC3164 syslog lines that match DIY-SIEM Graylog extractors (see `python -m diy_siem graylog-bootstrap`).
# Requires Syslog UDP input on port 5140 (scripts/bootstrap_inputs.sh).
set -euo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-5140}"
# Facility 16 (local0), severity 6 (info): PRI = 8*16+6 = 134
PRI="<134>"
send() {
  echo "${PRI}$1" | nc -u -w1 "${HOST}" "${PORT}"
  echo "Sent: $1"
}
# Same IP repeated → correlator brute-force rule (threshold 5 in diy_siem/correlator.py)
for i in 1 2 3 4 5; do
  send "diy-siem auth event=failed_login src_ip=203.0.113.10 user=demo_user attempt=${i}"
done
send "diy-siem windows EventID=4625 username=WIN\\\\demo_user ip=203.0.113.55 msg=An account failed to log on"
# Successful logon samples (4624 = Windows successful logon; event=success_login for Linux-style extractors)
send "diy-siem auth event=success_login src_ip=203.0.113.10 user=demo_user"
send "diy-siem windows EventID=4624 username=WIN\\\\demo_user ip=203.0.113.10 msg=An account was successfully logged on"
