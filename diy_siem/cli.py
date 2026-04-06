"""CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys

from diy_siem import db
from diy_siem.config import flask_host, flask_port
from diy_siem.correlator import run_all_poll_rules
from diy_siem.graylog_setup import bootstrap_graylog


def _cmd_poll() -> int:
    results = run_all_poll_rules()
    print(json.dumps(results, indent=2, default=str))
    return 0


def _cmd_test_db() -> int:
    aid = db.insert_alert(
        rule_name="manual_test",
        severity="info",
        summary="Database connectivity test",
        payload={"source": "cli test-db"},
    )
    print(f"inserted alert id={aid}")
    return 0


def _cmd_list() -> int:
    rows = db.list_recent_alerts(limit=20)
    print(json.dumps(rows, indent=2, default=str))
    return 0


def _cmd_explain(alert_id: int) -> int:
    from diy_siem.explain import explain_and_store_alert

    print(json.dumps(explain_and_store_alert(alert_id), indent=2, default=str))
    return 0


def _cmd_serve() -> int:
    from diy_siem.web import create_app

    app = create_app()
    print(f"Dashboard: http://{flask_host()}:{flask_port()}/")
    app.run(host=flask_host(), port=flask_port(), debug=False)
    return 0


def _cmd_graylog_bootstrap() -> int:
    result = bootstrap_graylog()
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="diy-siem", description="DIY SIEM correlation CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "poll",
        help="Run Graylog correlation (brute-force, after-hours, demo) and insert alerts when rules match",
    )
    sub.add_parser("test-db", help="Insert a single test row into Postgres (no Graylog)")
    sub.add_parser("list-alerts", help="Print recent alerts from Postgres")

    p_explain = sub.add_parser("explain", help="Generate Ollama explanation for an alert id and store it")
    p_explain.add_argument("alert_id", type=int, help="alerts.id from Postgres")

    sub.add_parser("serve", help="Run Flask dashboard (Chart.js + API)")

    sub.add_parser(
        "graylog-bootstrap",
        help="Create DIY-SIEM extractors + lab/auth/web streams in Graylog (idempotent; needs Syslog UDP 5140 input)",
    )

    args = parser.parse_args(argv)

    if args.command == "poll":
        return _cmd_poll()
    if args.command == "test-db":
        return _cmd_test_db()
    if args.command == "list-alerts":
        return _cmd_list()
    if args.command == "explain":
        return _cmd_explain(args.alert_id)
    if args.command == "serve":
        return _cmd_serve()
    if args.command == "graylog-bootstrap":
        return _cmd_graylog_bootstrap()

    return 1


if __name__ == "__main__":
    sys.exit(main())
