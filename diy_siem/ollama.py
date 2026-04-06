"""Call a local Ollama instance for plain-English alert explanations (no cloud)."""

from __future__ import annotations

import json
from typing import Any

import requests

from diy_siem.config import ollama_base_url, ollama_model, ollama_timeout_seconds


def build_prompt(
    rule_name: str,
    severity: str,
    summary: str | None,
    payload: dict[str, Any],
) -> str:
    ctx = json.dumps(payload, default=str)[:4000]
    return (
        "You are a SOC analyst assistant. Explain this security alert in plain English "
        "for a junior analyst.\n\n"
        "Requirements:\n"
        "- Write exactly 3 or 4 short sentences.\n"
        "- Sentence 1: what happened.\n"
        "- Sentence 2: why it could be risky or what to verify.\n"
        "- Sentence 3: one concrete action the analyst should take.\n"
        "- Optional sentence 4: only if needed for clarity.\n"
        "- Do not invent log fields that are not implied below.\n\n"
        f"Alert rule: {rule_name}\n"
        f"Severity: {severity}\n"
        f"Summary: {summary or '(none)'}\n"
        f"Context (JSON): {ctx}\n"
    )


def generate_explanation(
    rule_name: str,
    severity: str,
    summary: str | None,
    payload: dict[str, Any],
    *,
    timeout_seconds: int | None = None,
) -> str:
    """Blocking call to Ollama /api/generate. Raises requests.HTTPError or requests.RequestException."""
    base = ollama_base_url()
    model = ollama_model()
    effective_timeout = timeout_seconds if timeout_seconds is not None else ollama_timeout_seconds()
    prompt = build_prompt(rule_name, severity, summary, payload)
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3},
    }
    r = requests.post(
        f"{base}/api/generate",
        json=body,
        timeout=(5, effective_timeout),
    )
    r.raise_for_status()
    data = r.json()
    text = data.get("response", "")
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("Ollama returned an empty response")
    return text.strip()
