"""Flask dashboard — alerts + AI explanations + Chart.js stats."""

from __future__ import annotations

import base64
import binascii
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, url_for

from diy_siem import config, db
from diy_siem.config import (
    dashboard_auth_enabled,
    dashboard_basic_password,
    dashboard_basic_user,
    refresh_dotenv_from_cwd,
)
from diy_siem.report_pdf import build_alerts_pdf_bytes


def _authorization_is_basic(auth: object) -> bool:
    if auth is None:
        return False
    t = getattr(auth, "type", None)
    if isinstance(t, str):
        return t.lower() == "basic"
    s = str(t).lower()
    return s == "basic" or s.endswith(".basic")


def _basic_user_pass_from_header() -> tuple[str, str] | None:
    """Parse RFC 7617 Basic credentials from the raw Authorization header.

    Browsers send ``Basic <base64>``; parsing here avoids Werkzeug/Flask version quirks.
    """
    h = request.headers.get("Authorization", "")
    if len(h) < 7 or h[:6].lower() != "basic ":
        return None
    b64 = h[6:].strip()
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64, validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        decoded = raw.decode("latin-1")
    if ":" not in decoded:
        return None
    user, _, password = decoded.partition(":")
    return user.strip(), password


def _basic_user_pass_from_request() -> tuple[str, str] | None:
    direct = _basic_user_pass_from_header()
    if direct is not None:
        return direct
    auth = request.authorization
    if auth is None or not _authorization_is_basic(auth):
        return None
    return (auth.username or "").strip(), auth.password or ""


def _basic_auth_ok() -> bool:
    creds = _basic_user_pass_from_request()
    if creds is None:
        return False
    got_u, got_p = creds
    u = dashboard_basic_user()
    p = dashboard_basic_password()
    if not u or not p:
        return False
    return secrets.compare_digest(got_u.encode("utf-8"), u.encode("utf-8")) and secrets.compare_digest(
        got_p.encode("utf-8"), p.encode("utf-8")
    )


def _basic_auth_challenge() -> Response:
    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": f'Basic realm="{config.brand_name()} Dashboard"'},
        mimetype="text/plain",
    )


def create_app() -> Flask:
    refresh_dotenv_from_cwd()
    root = Path(__file__).resolve().parent
    static_dir = root / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app = Flask(
        __name__,
        template_folder=str(root / "templates"),
        static_folder=str(static_dir),
        static_url_path="/static",
    )
    app.config["JSON_SORT_KEYS"] = False

    def _brand_logo_filename() -> str | None:
        for name in ("logo.png", "logo.svg", "logo.webp"):
            if (static_dir / name).is_file():
                return name
        return None

    @app.context_processor
    def inject_brand() -> dict:
        fn = _brand_logo_filename()
        logo_url = url_for("static", filename=fn) if fn else None
        return {
            "brand_name": config.brand_name(),
            "brand_tagline": config.brand_tagline(),
            "brand_logo_url": logo_url,
        }

    @app.before_request
    def _require_dashboard_basic_auth() -> Response | None:
        if request.method == "OPTIONS":
            return None
        if not dashboard_auth_enabled():
            return None
        u = dashboard_basic_user()
        p = dashboard_basic_password()
        if not u or not p:
            return Response(
                "DASHBOARD_AUTH_ENABLED is true but DASHBOARD_USER or DASHBOARD_PASSWORD is missing",
                503,
                mimetype="text/plain",
            )
        if _basic_auth_ok():
            return None
        return _basic_auth_challenge()

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/stats")
    def api_stats():
        return jsonify(db.alert_stats())

    @app.route("/api/alerts")
    def api_alerts():
        rows = db.list_alerts_with_explanations(limit=200)
        for r in rows:
            for key in ("created_at", "ai_created_at"):
                v = r.get(key)
                if v is not None and hasattr(v, "isoformat"):
                    r[key] = v.isoformat()
        return jsonify(rows)

    @app.route("/api/report.pdf")
    def api_report_pdf():
        pdf = build_alerts_pdf_bytes()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return Response(
            pdf,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="siem-alerts-{stamp}.pdf"',
            },
        )

    return app
