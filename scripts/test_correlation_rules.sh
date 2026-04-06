#!/usr/bin/env bash
# Run unit tests for correlation rules (1) brute-force and (2) after-hours IST — no Docker/Graylog needed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

echo "Running correlation rule tests (mocked Graylog + Postgres)..."
echo "  Python: $PY"
echo ""

exec "$PY" -m unittest tests.test_correlation_rules -v
