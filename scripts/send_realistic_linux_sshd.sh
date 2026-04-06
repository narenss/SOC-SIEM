#!/usr/bin/env bash
# Realistic OpenSSH/sshd-style syslog lines for SOC demos (Syslog UDP -> Graylog :5140).
# Includes diy-siem auth key=value tail so extractors + correlator rules match.
set -euo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-5140}"
PRI="<134>"

send() {
  echo "${PRI}$1" | nc -u -w1 "${HOST}" "${PORT}"
  echo "Sent: ${1:0:120}..."
}

send "Apr  4 03:15:22 web01 sshd[4821]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2 | diy-siem auth event=failed_login src_ip=203.0.113.77 user=admin"
send "Apr  4 03:15:23 web01 sshd[4821]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2 | diy-siem auth event=failed_login src_ip=203.0.113.77 user=admin"
send "Apr  4 03:15:24 web01 sshd[4821]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2 | diy-siem auth event=failed_login src_ip=203.0.113.77 user=admin"
send "Apr  4 03:15:25 web01 sshd[4821]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2 | diy-siem auth event=failed_login src_ip=203.0.113.77 user=admin"
send "Apr  4 03:15:26 web01 sshd[4821]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2 | diy-siem auth event=failed_login src_ip=203.0.113.77 user=admin"
send "Apr  4 03:16:01 web01 sshd[5100]: Accepted password for deploy from 198.51.100.20 port 22 ssh2 | diy-siem auth event=success_login src_ip=198.51.100.20 user=deploy"

echo "Done (${HOST}:${PORT}/udp)."
