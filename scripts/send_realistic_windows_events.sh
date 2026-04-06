#!/usr/bin/env bash
# Windows Security-style lines (4625 failed logon, 4624 success, 4672 admin) over Syslog UDP.
# Uses the same EventID= / ip= patterns as graylog-bootstrap extractors; correlator matches 4624/4625.
# Usage: ./scripts/send_realistic_windows_events.sh [host] [port]
set -euo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-5140}"
PRI="<134>"
send() {
  echo "${PRI}$1" | nc -u -w1 "${HOST}" "${PORT}"
  echo "Sent: ${1:0:130}..."
}

for i in 1 2 3 4 5; do
  send "diy-siem windows EventID=4625 username=CONTOSO\\\\svc_batch ip=203.0.113.200 msg=An account failed to log on (sample ${i}) LogonType=3"
done
send "diy-siem windows EventID=4624 username=CONTOSO\\\\svc_batch ip=203.0.113.200 msg=An account was successfully logged on LogonType=3"
send "diy-siem windows EventID=4672 username=CONTOSO\\\\Administrator ip=198.51.100.10 msg=Special privileges assigned to new logon"
echo "Done (${HOST}:${PORT}/udp). Pair with Winlogbeat on :5044 using examples/winlogbeat-graylog.yml for live Windows hosts."
