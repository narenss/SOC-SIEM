#!/usr/bin/env bash
# Apache combined + nginx combined log-style lines (Syslog UDP → Graylog :5140).
# Messages include diy-siem web so they route to the DIY-SIEM Web stream after bootstrap.
# Usage: ./scripts/send_realistic_apache_nginx.sh [host] [port]
set -euo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-5140}"
PRI="<134>"
send() {
  echo "${PRI}$1" | nc -u -w1 "${HOST}" "${PORT}"
  echo "Sent: ${1:0:140}..."
}

send "Apr  4 12:01:03 edge apache2[1204]: 203.0.113.44 - - [04/Apr/2026:12:01:03 +0000] \"GET /login.php HTTP/1.1\" 200 4521 \"-\" \"curl/8.4.0\" | diy-siem web vhost=www.example.com svc=apache status=200 uri=/login.php"
send "Apr  4 12:01:04 edge apache2[1204]: 203.0.113.44 - - [04/Apr/2026:12:01:04 +0000] \"POST /login.php HTTP/1.1\" 401 512 \"-\" \"Mozilla/5.0\" | diy-siem web vhost=www.example.com svc=apache status=401 uri=/login.php"
send "Apr  4 12:01:10 edge nginx[881]: 198.51.100.5 - - [04/Apr/2026:12:01:10 +0000] \"GET /api/health HTTP/1.1\" 200 48 \"-\" \"kube-probe/1.29\" | diy-siem web vhost=api.internal svc=nginx status=200 uri=/api/health"
send "Apr  4 12:02:01 edge nginx[881]: 203.0.113.99 - - [04/Apr/2026:12:02:01 +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"python-requests/2.31.0\" | diy-siem web vhost=cdn.example.com svc=nginx status=404 uri=/.env"
echo "Done (${HOST}:${PORT}/udp). Search in Graylog: diy-siem web"
