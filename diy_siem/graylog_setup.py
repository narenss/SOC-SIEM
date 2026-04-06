"""Idempotent Graylog setup: extractors on Syslog UDP + lab/auth/web streams (+ resume).

Uses the same REST base URL and credentials as `diy_siem.graylog.search_relative`.
See Graylog 6.x API: `/api/system/inputs`, `/api/streams`, `/api/system/indices/index_sets`.
"""

from __future__ import annotations

from typing import Any

import requests

from diy_siem.config import graylog_auth, graylog_base_url

_HEADERS = {
    "Accept": "application/json",
    "X-Requested-By": "diy-siem-graylog-setup",
}

SYSLOG_UDP_TYPE = "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
SYSLOG_UDP_PORT = 5140

# Human-readable titles so we skip duplicates on re-run.
EXTRACTOR_SPECS: list[dict[str, Any]] = [
    {
        "title": "DIY-SIEM: src_ip (key=value)",
        "target_field": "src_ip",
        "regex_value": r"src_ip=(\S+)",
        "order": 0,
    },
    {
        "title": "DIY-SIEM: user (key=value)",
        "target_field": "user",
        "regex_value": r"user=(\S+)",
        "order": 1,
    },
    {
        "title": "DIY-SIEM: username alternate",
        "target_field": "user",
        "regex_value": r"username=(\S+)",
        "order": 2,
    },
    {
        "title": "DIY-SIEM: event (key=value)",
        "target_field": "event",
        "regex_value": r"event=(\S+)",
        "order": 3,
    },
    {
        "title": "DIY-SIEM: Windows-style EventID",
        "target_field": "win_event_id",
        "regex_value": r"EventID=(\d+)",
        "order": 4,
    },
]

STREAM_LAB_TITLE = "DIY-SIEM Lab"
STREAM_AUTH_TITLE = "DIY-SIEM Authentication"
STREAM_WEB_TITLE = "DIY-SIEM Web"


def _request(method: str, path: str, **kwargs: Any) -> requests.Response:
    base = graylog_base_url().rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    url = f"{base}{path}"
    extra_headers = kwargs.pop("headers", None)
    merged = {**_HEADERS, **(extra_headers or {})}
    return requests.request(
        method,
        url,
        auth=graylog_auth(),
        headers=merged,
        timeout=60,
        **kwargs,
    )


def _get_json(path: str) -> dict[str, Any]:
    r = _request("GET", path)
    r.raise_for_status()
    out = r.json()
    if not isinstance(out, dict):
        raise RuntimeError(f"Unexpected JSON from {path!r}")
    return out


def find_syslog_udp_input_id() -> str | None:
    data = _get_json("/api/system/inputs")
    inputs = data.get("inputs")
    if not isinstance(inputs, list):
        return None
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        if inp.get("type") != SYSLOG_UDP_TYPE:
            continue
        attrs = inp.get("attributes") or {}
        if not isinstance(attrs, dict):
            continue
        try:
            port = int(attrs.get("port"))
        except (TypeError, ValueError):
            continue
        if port == SYSLOG_UDP_PORT:
            iid = inp.get("id")
            return str(iid) if iid is not None else None
    return None


def default_index_set_id() -> str:
    data = _get_json("/api/system/indices/index_sets")
    index_sets = data.get("index_sets")
    if not isinstance(index_sets, list):
        raise RuntimeError("Graylog index_sets response missing 'index_sets' list")
    for s in index_sets:
        if isinstance(s, dict) and s.get("default") is True:
            sid = s.get("id")
            if sid:
                return str(sid)
    raise RuntimeError("No default Graylog index set found (expected one with default: true)")


def _extractor_titles(input_id: str) -> set[str]:
    data = _get_json(f"/api/system/inputs/{input_id}/extractors")
    ext = data.get("extractors")
    if not isinstance(ext, list):
        return set()
    titles: set[str] = set()
    for e in ext:
        if isinstance(e, dict):
            t = e.get("title")
            if isinstance(t, str):
                titles.add(t)
    return titles


def ensure_extractors(input_id: str) -> list[str]:
    existing = _extractor_titles(input_id)
    created: list[str] = []
    for spec in EXTRACTOR_SPECS:
        title = spec["title"]
        if title in existing:
            continue
        body = {
            "title": title,
            "cursor_strategy": "copy",
            "source_field": "message",
            "target_field": spec["target_field"],
            "extractor_type": "regex",
            "extractor_config": {"regex_value": spec["regex_value"]},
            "converters": [],
            "condition_type": "none",
            "condition_value": "",
            "order": int(spec["order"]),
        }
        r = _request(
            "POST",
            f"/api/system/inputs/{input_id}/extractors",
            json=body,
        )
        r.raise_for_status()
        created.append(title)
    return created


def _list_streams() -> list[dict[str, Any]]:
    data = _get_json("/api/streams")
    streams = data.get("streams")
    if not isinstance(streams, list):
        return []
    return [s for s in streams if isinstance(s, dict)]


def _find_stream_id_by_title(title: str) -> str | None:
    for s in _list_streams():
        if s.get("title") == title:
            sid = s.get("id")
            return str(sid) if sid else None
    return None


def ensure_stream(
    *,
    title: str,
    description: str,
    rules: list[dict[str, Any]],
    matching_type: str,
    index_set_id: str,
) -> dict[str, Any]:
    sid = _find_stream_id_by_title(title)
    if sid:
        r_resume = _request("POST", f"/api/streams/{sid}/resume")
        r_resume.raise_for_status()
        return {"title": title, "action": "exists", "stream_id": sid, "resumed": True}

    body = {
        "title": title,
        "description": description,
        "rules": rules,
        "matching_type": matching_type,
        "remove_matches_from_default_stream": False,
        "index_set_id": index_set_id,
    }
    r = _request(
        "POST",
        "/api/streams",
        json=body,
    )
    r.raise_for_status()
    created = r.json()
    new_id = created.get("stream_id") if isinstance(created, dict) else None
    if not new_id:
        raise RuntimeError(f"Create stream {title!r} did not return stream_id: {created!r}")
    new_id = str(new_id)
    rr = _request("POST", f"/api/streams/{new_id}/resume")
    rr.raise_for_status()
    return {"title": title, "action": "created", "stream_id": new_id, "resumed": rr.status_code == 204}


def bootstrap_graylog() -> dict[str, Any]:
    """
    Ensure Syslog UDP extractors and DIY-SIEM streams exist; resume streams.

    Returns a JSON-serializable summary for the CLI.
    """
    input_id = find_syslog_udp_input_id()
    if not input_id:
        return {
            "ok": False,
            "error": f"No Syslog UDP input on port {SYSLOG_UDP_PORT} found. Run scripts/bootstrap_inputs.sh first.",
        }

    index_set_id = default_index_set_id()
    extractors_created = ensure_extractors(input_id)

    # StreamRuleType.CONTAINS == 6 (message contains substring)
    lab = ensure_stream(
        title=STREAM_LAB_TITLE,
        description="All diy-siem tagged traffic (syslog or GELF short_message).",
        rules=[{"type": 6, "value": "diy-siem", "field": "message", "inverted": False}],
        matching_type="OR",
        index_set_id=index_set_id,
    )
    auth = ensure_stream(
        title=STREAM_AUTH_TITLE,
        description="Auth-style diy-siem samples (message contains 'diy-siem auth').",
        rules=[{"type": 6, "value": "diy-siem auth", "field": "message", "inverted": False}],
        matching_type="OR",
        index_set_id=index_set_id,
    )
    web = ensure_stream(
        title=STREAM_WEB_TITLE,
        description="Web access-style samples (message contains 'diy-siem web').",
        rules=[{"type": 6, "value": "diy-siem web", "field": "message", "inverted": False}],
        matching_type="OR",
        index_set_id=index_set_id,
    )

    return {
        "ok": True,
        "syslog_input_id": input_id,
        "default_index_set_id": index_set_id,
        "extractors_created": extractors_created,
        "streams": [lab, auth, web],
    }
