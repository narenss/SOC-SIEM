"""Correlation rules — demo marker plus auth-focused rules (Graylog + Postgres)."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from diy_siem import db
from diy_siem.config import ollama_enabled
from diy_siem.explain import explain_and_store_alert
from diy_siem.graylog import message_count_and_sample, messages_from_search, search_relative

# Demo: matches your syslog test script (`send_test_syslog.sh`).
DEMO_RULE_NAME = "demo_diy_siem_marker"
DEMO_QUERY = "diy-siem"
DEDUP_WINDOW_MINUTES = 10

# Auth rules — align queries with `scripts/send_auth_sample_syslog.sh` and Graylog extractors in `graylog_setup.py`.
BRUTE_FORCE_RULE_PREFIX = "auth_brute_force"
BRUTE_FORCE_QUERY = "diy-siem AND (event:failed_login OR win_event_id:4625)"
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_SEVERITY = "high"
MITRE_BRUTE_FORCE = "T1110"

AFTER_HOURS_RULE_PREFIX = "after_hours_login"
AFTER_HOURS_QUERY = "diy-siem AND (event:success_login OR win_event_id:4624)"
AFTER_HOURS_SEVERITY = "medium"
MITRE_AFTER_HOURS = "T1078"

# Business hours in IST (Asia/Kolkata): [start, end) by clock hour, e.g. 8–18 → 08:00 inclusive through 17:59.
BUSINESS_TIMEZONE = ZoneInfo("Asia/Kolkata")
BUSINESS_HOUR_START = 8
BUSINESS_HOUR_END = 18

_IP_KV = re.compile(r"\b(?:src_ip|ip)=(\S+)")


def _parse_graylog_timestamp(msg: dict[str, Any]) -> datetime | None:
    ts = msg.get("timestamp")
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts) / 1000.0, tz=timezone.utc)
    if isinstance(ts, str):
        s = ts.strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None
    return None


def is_outside_business_hours_ist(dt: datetime) -> bool:
    """True if the instant falls outside [BUSINESS_HOUR_START, BUSINESS_HOUR_END) in IST."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ist = dt.astimezone(BUSINESS_TIMEZONE)
    h = ist.hour
    return h < BUSINESS_HOUR_START or h >= BUSINESS_HOUR_END


def _text(msg: dict[str, Any]) -> str:
    for k in ("message", "full_message"):
        v = msg.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return ""


def _failure_bucket_key(msg: dict[str, Any]) -> str:
    sip = msg.get("src_ip")
    if isinstance(sip, str) and sip.strip():
        return f"ip:{sip.strip()}"
    text = _text(msg)
    m = _IP_KV.search(text)
    if m:
        return f"ip:{m.group(1).strip()}"
    user = msg.get("user")
    if isinstance(user, str) and user.strip():
        return f"user:{user.strip()}"
    return "unknown"


def _graylog_message_id(msg: dict[str, Any]) -> str | None:
    mid = msg.get("id") or msg.get("_id")
    if mid is None:
        return None
    return str(mid)


def run_auth_brute_force_rule(*, range_seconds: int = 600) -> dict[str, Any]:
    """
    Many failed auth attempts for the same source (src_ip or user) in the window → one alert per source (deduped).
    MITRE: T1110 (Brute Force).
    """
    raw = search_relative(BRUTE_FORCE_QUERY, range_seconds=range_seconds, limit=500)
    msgs = messages_from_search(raw)
    if not msgs:
        return {
            "rule": BRUTE_FORCE_RULE_PREFIX,
            "fired": False,
            "reason": "no_matching_messages",
            "total": 0,
        }

    counts = Counter(_failure_bucket_key(m) for m in msgs)
    offenders = [(k, n) for k, n in counts.items() if n >= BRUTE_FORCE_THRESHOLD]
    if not offenders:
        return {
            "rule": BRUTE_FORCE_RULE_PREFIX,
            "fired": False,
            "reason": "below_threshold",
            "total": len(msgs),
            "threshold": BRUTE_FORCE_THRESHOLD,
            "by_bucket": dict(counts),
        }

    offenders.sort(key=lambda x: (-x[1], x[0]))
    fired: list[dict[str, Any]] = []
    for bucket, n_fail in offenders:
        rule_name = f"{BRUTE_FORCE_RULE_PREFIX}:{bucket}"
        if db.count_recent_alerts(rule_name, DEDUP_WINDOW_MINUTES) > 0:
            continue
        sample = next((m for m in msgs if _failure_bucket_key(m) == bucket), msgs[0])
        summary = (
            f"Possible brute-force activity: {n_fail} failed authentication attempts in {range_seconds}s "
            f"for {bucket.replace(':', '=', 1)}."
        )
        payload: dict[str, Any] = {
            "query": BRUTE_FORCE_QUERY,
            "range_seconds": range_seconds,
            "bucket": bucket,
            "failure_count": n_fail,
            "threshold": BRUTE_FORCE_THRESHOLD,
            "by_bucket": dict(counts),
            "sample_message": sample,
        }
        alert_id = db.insert_alert(
            rule_name=rule_name,
            severity=BRUTE_FORCE_SEVERITY,
            summary=summary,
            payload=payload,
            graylog_message_id=_graylog_message_id(sample),
            mitre_technique=MITRE_BRUTE_FORCE,
        )
        entry: dict[str, Any] = {
            "rule": rule_name,
            "fired": True,
            "alert_id": alert_id,
            "bucket": bucket,
            "failures": n_fail,
            "mitre_technique": MITRE_BRUTE_FORCE,
        }
        if ollama_enabled():
            entry["explanation"] = explain_and_store_alert(alert_id)
        fired.append(entry)

    if not fired:
        bucket, n_fail = offenders[0]
        rule_name = f"{BRUTE_FORCE_RULE_PREFIX}:{bucket}"
        return {
            "rule": rule_name,
            "fired": False,
            "reason": "deduplicated",
            "total": len(msgs),
            "bucket": bucket,
            "failures": n_fail,
        }

    if len(fired) == 1:
        return fired[0]
    return {
        "rule": BRUTE_FORCE_RULE_PREFIX,
        "fired": True,
        "alerts": fired,
        "count": len(fired),
    }


def run_after_hours_login_rule(*, range_seconds: int = 600) -> dict[str, Any]:
    """
    Successful login events whose Graylog timestamp falls outside IST business hours.
    MITRE: T1078 (Valid Accounts — suspicious use / timing).
    """
    raw = search_relative(AFTER_HOURS_QUERY, range_seconds=range_seconds, limit=200)
    msgs = messages_from_search(raw)
    suspicious: list[dict[str, Any]] = []
    for m in msgs:
        dt = _parse_graylog_timestamp(m)
        if dt is None:
            continue
        if is_outside_business_hours_ist(dt):
            suspicious.append(m)

    if not suspicious:
        return {
            "rule": AFTER_HOURS_RULE_PREFIX,
            "fired": False,
            "reason": "no_after_hours_success_logins",
            "total": len(msgs),
        }

    def _user_key(m: dict[str, Any]) -> str:
        u = m.get("user")
        if isinstance(u, str) and u.strip():
            return u.strip()
        return "unknown"

    by_user: dict[str, list[dict[str, Any]]] = {}
    for m in suspicious:
        by_user.setdefault(_user_key(m), []).append(m)

    fired: list[dict[str, Any]] = []
    for user_key in sorted(by_user.keys()):
        rule_name = f"{AFTER_HOURS_RULE_PREFIX}:{user_key}"
        if db.count_recent_alerts(rule_name, DEDUP_WINDOW_MINUTES) > 0:
            continue
        sample = by_user[user_key][0]
        dt = _parse_graylog_timestamp(sample)
        ist_ts = dt.astimezone(BUSINESS_TIMEZONE).isoformat(timespec="seconds") if dt else ""
        summary = (
            f"Successful login outside business hours ({BUSINESS_HOUR_START}:00–{BUSINESS_HOUR_END}:00 IST) "
            f"for user {user_key} (event time {ist_ts})."
        )
        payload: dict[str, Any] = {
            "query": AFTER_HOURS_QUERY,
            "range_seconds": range_seconds,
            "matches": len(by_user[user_key]),
            "user": user_key,
            "sample_message": sample,
        }
        alert_id = db.insert_alert(
            rule_name=rule_name,
            severity=AFTER_HOURS_SEVERITY,
            summary=summary,
            payload=payload,
            graylog_message_id=_graylog_message_id(sample),
            mitre_technique=MITRE_AFTER_HOURS,
        )
        entry: dict[str, Any] = {
            "rule": rule_name,
            "fired": True,
            "alert_id": alert_id,
            "user": user_key,
            "mitre_technique": MITRE_AFTER_HOURS,
        }
        if ollama_enabled():
            entry["explanation"] = explain_and_store_alert(alert_id)
        fired.append(entry)

    if not fired:
        return {
            "rule": AFTER_HOURS_RULE_PREFIX,
            "fired": False,
            "reason": "deduplicated",
            "total": len(suspicious),
            "users": list(by_user.keys()),
        }

    if len(fired) == 1:
        return fired[0]
    return {
        "rule": AFTER_HOURS_RULE_PREFIX,
        "fired": True,
        "alerts": fired,
        "count": len(fired),
    }


def run_all_poll_rules(*, range_seconds: int = 600) -> list[dict[str, Any]]:
    """Run correlation rules in order: auth brute-force, after-hours success, demo marker."""
    return [
        run_auth_brute_force_rule(range_seconds=range_seconds),
        run_after_hours_login_rule(range_seconds=range_seconds),
        run_demo_rule(range_seconds=range_seconds),
    ]


def run_demo_rule(*, range_seconds: int = 600) -> dict[str, Any]:
    """
    If any message in the window contains the demo marker, raise one alert (deduplicated).
    Replace this with real rules (brute force, after-hours, etc.) as log fields improve.
    """
    raw = search_relative(DEMO_QUERY, range_seconds=range_seconds)
    total, sample = message_count_and_sample(raw)

    if total < 1:
        return {"rule": DEMO_RULE_NAME, "fired": False, "reason": "no_matching_messages", "total": total}

    if db.count_recent_alerts(DEMO_RULE_NAME, DEDUP_WINDOW_MINUTES) > 0:
        return {
            "rule": DEMO_RULE_NAME,
            "fired": False,
            "reason": "deduplicated",
            "total": total,
        }

    msg_id = None
    summary = f"Observed {total} message(s) matching demo query in Graylog."
    payload: dict[str, Any] = {
        "query": DEMO_QUERY,
        "graylog_total": total,
        "sample_message": sample,
    }
    if sample:
        msg_id = sample.get("id") or sample.get("_id")
        if msg_id is not None:
            msg_id = str(msg_id)
        first_line = sample.get("message") or sample.get("full_message")
        if isinstance(first_line, str):
            summary = first_line[:500]

    alert_id = db.insert_alert(
        rule_name=DEMO_RULE_NAME,
        severity="low",
        summary=summary,
        payload=payload,
        graylog_message_id=msg_id,
        mitre_technique=None,
    )
    out: dict[str, Any] = {
        "rule": DEMO_RULE_NAME,
        "fired": True,
        "alert_id": alert_id,
        "total": total,
    }
    if ollama_enabled():
        out["explanation"] = explain_and_store_alert(alert_id)
    return out
