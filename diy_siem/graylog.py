"""Graylog REST API helpers for correlation polling."""

from __future__ import annotations

from typing import Any

import requests

from diy_siem.config import graylog_auth, graylog_base_url

_HEADERS = {
    "Accept": "application/json",
    "X-Requested-By": "diy-siem",
}


def search_relative(
    query: str,
    *,
    range_seconds: int = 300,
    limit: int = 150,
) -> dict[str, Any]:
    """
    Run a relative time search on Graylog 6+ and normalize output.
    """
    base = graylog_base_url()
    url = f"{base}/api/search/messages"
    body = {
        "query": query,
        "timerange": {"type": "relative", "range": int(range_seconds)},
        "size": int(limit),
        "from": 0,
        "sort": "timestamp",
        "sort_order": "desc",
        "fields": [
            "message",
            "full_message",
            "timestamp",
            "source",
            "src_ip",
            "ip",
            "user",
            "username",
            "event",
            "win_event_id",
            "gl2_message_id",
        ],
        "streams": [],
    }
    r = requests.post(
        url,
        json=body,
        auth=graylog_auth(),
        headers=_HEADERS,
        timeout=60,
    )
    r.raise_for_status()
    return r.json()


def message_count_and_sample(data: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
    """Return total hit count (best effort) and one raw message dict if present."""
    parsed = messages_from_search(data)

    total = data.get("total_results")
    if total is None:
        total = len(parsed)
    else:
        try:
            total = int(total)
        except (TypeError, ValueError):
            total = len(parsed)

    sample_inner: dict[str, Any] | None = None
    if parsed and isinstance(parsed[0], dict):
        sample_inner = parsed[0]

    return total, sample_inner


def messages_from_search(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract message dicts from Graylog search response.

    Supports both:
    - Graylog 6 `/api/search/messages` (`schema` + `datarows`)
    - Legacy `/api/search/universal/relative` (`messages`)
    """
    # Graylog 6 format
    schema = data.get("schema")
    rows = data.get("datarows")
    if isinstance(schema, list) and isinstance(rows, list):
        fields: list[str] = []
        for col in schema:
            if isinstance(col, dict):
                field = col.get("field")
                fields.append(str(field) if field is not None else "")
            else:
                fields.append("")
        out: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, list):
                continue
            msg: dict[str, Any] = {}
            for i, value in enumerate(row):
                if i >= len(fields):
                    break
                f = fields[i]
                if f:
                    msg[f] = value
            if "gl2_message_id" in msg and "id" not in msg:
                msg["id"] = msg["gl2_message_id"]
            out.append(msg)
        return out

    # Legacy universal search format
    messages = data.get("messages")
    if not isinstance(messages, list):
        return []
    out: list[dict[str, Any]] = []
    for item in messages:
        if isinstance(item, dict):
            inner = item.get("message")
            if isinstance(inner, dict):
                out.append(inner)
    return out
