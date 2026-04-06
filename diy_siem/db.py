"""PostgreSQL access for alerts and explanations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from contextlib import contextmanager
from typing import Any

import psycopg2
import psycopg2.extras

from diy_siem.config import database_url


@contextmanager
def get_connection():
    conn = psycopg2.connect(database_url())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def insert_alert(
    rule_name: str,
    severity: str,
    summary: str | None,
    payload: Mapping[str, Any],
    graylog_message_id: str | None = None,
    mitre_technique: str | None = None,
) -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (rule_name, severity, summary, payload, graylog_message_id, mitre_technique)
                VALUES (%s, %s, %s, %s::jsonb, %s, %s)
                RETURNING id
                """,
                (
                    rule_name,
                    severity,
                    summary,
                    json.dumps(payload, default=str),
                    graylog_message_id,
                    mitre_technique,
                ),
            )
            row = cur.fetchone()
            assert row is not None
            return int(row[0])


def insert_explanation(alert_id: int, model: str, explanation: str) -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alert_explanations (alert_id, model, explanation)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (alert_id, model, explanation),
            )
            row = cur.fetchone()
            assert row is not None
            return int(row[0])


def count_recent_alerts(rule_name: str, window_minutes: int) -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) FROM alerts
                WHERE rule_name = %s
                  AND created_at > NOW() - (%s * INTERVAL '1 minute')
                """,
                (rule_name, window_minutes),
            )
            row = cur.fetchone()
            return int(row[0]) if row else 0


def list_recent_alerts(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, created_at, rule_name, severity, summary, payload, graylog_message_id, mitre_technique
                FROM alerts
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]


def get_alert_by_id(alert_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, created_at, rule_name, severity, summary, payload, graylog_message_id, mitre_technique
                FROM alerts WHERE id = %s
                """,
                (alert_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def list_alerts_with_explanations(limit: int = 100) -> list[dict[str, Any]]:
    """Latest explanation per alert (if any), for the dashboard."""
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    a.id,
                    a.created_at,
                    a.rule_name,
                    a.severity,
                    a.summary,
                    a.payload,
                    a.graylog_message_id,
                    a.mitre_technique,
                    ex.explanation AS ai_explanation,
                    ex.model AS ai_model,
                    ex.created_at AS ai_created_at
                FROM alerts a
                LEFT JOIN LATERAL (
                    SELECT explanation, model, created_at
                    FROM alert_explanations
                    WHERE alert_id = a.id
                    ORDER BY created_at DESC
                    LIMIT 1
                ) ex ON true
                ORDER BY a.created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]


def alert_stats() -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT rule_name, COUNT(*)::int AS count
                FROM alerts
                GROUP BY rule_name
                ORDER BY count DESC
                """
            )
            by_rule = [dict(r) for r in cur.fetchall()]
            cur.execute(
                """
                SELECT severity, COUNT(*)::int AS count
                FROM alerts
                GROUP BY severity
                ORDER BY count DESC
                """
            )
            by_severity = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT COUNT(*)::int AS total FROM alerts")
            total = cur.fetchone()
            n = int(total["total"]) if total else 0
            cur.execute(
                """
                SELECT COUNT(DISTINCT alert_id)::int AS with_ai
                FROM alert_explanations
                """
            )
            with_ai_row = cur.fetchone()
            with_ai = int(with_ai_row["with_ai"]) if with_ai_row else 0
        return {
            "total_alerts": n,
            "alerts_with_explanation": with_ai,
            "by_rule": by_rule,
            "by_severity": by_severity,
        }
