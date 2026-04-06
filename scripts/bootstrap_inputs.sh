#!/usr/bin/env bash
# Create global Syslog UDP (5140), GELF TCP (12201), and Beats TCP (5044) inputs via Graylog REST API if absent.
set -euo pipefail
GRAYLOG_URL="${GRAYLOG_URL:-http://127.0.0.1:9000}"
USER="${GRAYLOG_USER:-admin}"
PASS="${GRAYLOG_PASSWORD:-admin}"

wait_for_api() {
  local i=0
  while ! curl -fsS -u "${USER}:${PASS}" "${GRAYLOG_URL}/api/system" >/dev/null 2>&1; do
    i=$((i + 1))
    if [[ "${i}" -gt 120 ]]; then
      echo "Timeout waiting for Graylog at ${GRAYLOG_URL}" >&2
      exit 1
    fi
    sleep 2
  done
}

input_exists() {
  local t="$1"
  curl -fsS -u "${USER}:${PASS}" "${GRAYLOG_URL}/api/system/inputs" | grep -q "\"type\":\"${t}\""
}

create_input() {
  local title="$1"
  local type="$2"
  local json="$3"
  curl -fsS -u "${USER}:${PASS}" -X POST "${GRAYLOG_URL}/api/system/inputs" \
    -H "Content-Type: application/json" \
    -H "X-Requested-By: cli" \
    -d "{\"title\":\"${title}\",\"type\":\"${type}\",\"global\":true,\"configuration\":${json}}" \
    | cat
  echo ""
}

wait_for_api
echo "Graylog API is up."

if input_exists "org.graylog2.inputs.syslog.udp.SyslogUDPInput"; then
  echo "Syslog UDP input already present."
else
  echo "Creating Syslog UDP input on 0.0.0.0:5140..."
  create_input "Syslog UDP (docker)" "org.graylog2.inputs.syslog.udp.SyslogUDPInput" \
    '{"bind_address":"0.0.0.0","port":5140,"recv_buffer_size":262144,"number_worker_threads":4}'
fi

# Graylog registers this type as GELFTCPInput (capital TCP), not GelfTCPInput.
GELF_TCP_TYPE="org.graylog2.inputs.gelf.tcp.GELFTCPInput"
if input_exists "${GELF_TCP_TYPE}"; then
  echo "GELF TCP input already present."
else
  echo "Creating GELF TCP input on 0.0.0.0:12201..."
  create_input "GELF TCP (docker)" "${GELF_TCP_TYPE}" \
    '{"bind_address":"0.0.0.0","port":12201,"tls_enable":false,"use_null_delimiter":false,"tcp_keepalive":false,"number_worker_threads":4,"tls_cert_file":"","tls_key_file":"","tls_key_password":"","tls_client_auth_cert_file":"","tls_client_auth":false,"tls_require_cert":false}'
fi

# Graylog 6.x: Beats (Filebeat / Winlogbeat) use the Logstash-compatible Beats input.
BEATS2_TYPE="org.graylog.plugins.beats.Beats2Input"
if input_exists "${BEATS2_TYPE}"; then
  echo "Beats TCP input already present."
else
  echo "Creating Beats TCP input on 0.0.0.0:5044..."
  create_input "Beats TCP (docker)" "${BEATS2_TYPE}" \
    '{"bind_address":"0.0.0.0","port":5044,"recv_buffer_size":1048576,"number_worker_threads":4,"tls_enable":false,"tcp_keepalive":false,"tls_cert_file":"","tls_key_file":"","tls_key_password":"","tls_client_auth":"disabled","tls_client_auth_cert_file":"","no_beats_prefix":false}'
fi

echo "Done. Send a test with: ./scripts/send_test_syslog.sh"
echo "Optional: python -m diy_siem graylog-bootstrap  (extractors + streams; see README)"
