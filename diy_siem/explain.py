"""Attach LLM explanations to alerts (Postgres)."""

from __future__ import annotations

from typing import Any

from diy_siem import db
from diy_siem.config import ollama_enabled, ollama_model
from diy_siem.ollama import generate_explanation


def explain_and_store_alert(alert_id: int) -> dict[str, Any]:
    """Fetch alert row, call Ollama, insert alert_explanations row."""
    row = db.get_alert_by_id(alert_id)
    if row is None:
        return {"ok": False, "error": "alert_not_found", "alert_id": alert_id}

    if not ollama_enabled():
        return {"ok": False, "error": "ollama_disabled", "alert_id": alert_id}

    payload = row.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}

    try:
        text = generate_explanation(
            row["rule_name"],
            row["severity"],
            row.get("summary"),
            payload,
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": "ollama_failed",
            "detail": str(exc),
            "alert_id": alert_id,
        }

    mid = ollama_model()
    eid = db.insert_explanation(alert_id, mid, text)
    return {"ok": True, "alert_id": alert_id, "explanation_id": eid, "model": mid}
