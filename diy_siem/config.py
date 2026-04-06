"""Load settings from the environment (optional `.env` in project root)."""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None  # type: ignore[misc, assignment]


def _load_dotenv() -> None:
    if load_dotenv is None:
        return
    # Package parent dir (editable install: repo/.env next to diy_siem/)
    pkg_root = Path(__file__).resolve().parent.parent
    pkg_env = pkg_root / ".env"
    if pkg_env.is_file():
        load_dotenv(pkg_env, override=True)
    # Project dir when CWD is the repo (fixes pip install . where __file__ is site-packages)
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file() and cwd_env.resolve() != pkg_env.resolve():
        load_dotenv(cwd_env, override=True)
    elif not pkg_env.is_file() and cwd_env.is_file():
        load_dotenv(cwd_env)


_load_dotenv()


def refresh_dotenv_from_cwd() -> None:
    """Re-load `.env` from the current working directory (override).

    Call this when creating the Flask app so `python -m diy_siem serve` always
    picks up the repo's `.env` even if the package is installed under site-packages.
    """
    if load_dotenv is None:
        return
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        load_dotenv(cwd_env, override=True)


def _get(name: str, default: str | None = None) -> str:
    val = os.environ.get(name, default)
    if val is None or val == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val


def database_url() -> str:
    explicit = os.environ.get("DATABASE_URL", "").strip()
    if explicit:
        return explicit
    user = os.environ.get("POSTGRES_USER", "diy_siem")
    password = _get("POSTGRES_PASSWORD")
    host = os.environ.get("POSTGRES_HOST", "127.0.0.1")
    port = os.environ.get("POSTGRES_PORT", "5432")
    database = os.environ.get("POSTGRES_DB", "diy_siem")
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


def graylog_base_url() -> str:
    return os.environ.get("GRAYLOG_API_URL", "http://127.0.0.1:9000").rstrip("/")


def graylog_auth() -> tuple[str, str]:
    user = os.environ.get("GRAYLOG_USERNAME", "admin")
    password = os.environ.get("GRAYLOG_PASSWORD", "admin")
    return user, password


def ollama_enabled() -> bool:
    return os.environ.get("OLLAMA_ENABLED", "true").lower() in ("1", "true", "yes")


def ollama_base_url() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")


def ollama_model() -> str:
    return os.environ.get("OLLAMA_MODEL", "llama3.2")


def ollama_timeout_seconds() -> int:
    raw = os.environ.get("OLLAMA_TIMEOUT_SECONDS", "25").strip()
    try:
        val = int(raw)
    except ValueError:
        return 25
    return max(1, val)


def flask_host() -> str:
    return os.environ.get("FLASK_HOST", "127.0.0.1")


def flask_port() -> int:
    return int(os.environ.get("FLASK_PORT", "5000"))


def brand_name() -> str:
    return os.environ.get("SIEM_BRAND_NAME", "Amrita SIEM")


def brand_tagline() -> str:
    return os.environ.get(
        "SIEM_BRAND_TAGLINE",
        "Correlation + PostgreSQL + local Ollama — logs ingested via Graylog",
    )


def dashboard_auth_enabled() -> bool:
    v = os.environ.get("DASHBOARD_AUTH_ENABLED", "").strip().strip('"').strip("'")
    return v.lower() in ("1", "true", "yes", "on")


def dashboard_basic_user() -> str:
    return os.environ.get("DASHBOARD_USER", "").strip()


def dashboard_basic_password() -> str:
    return os.environ.get("DASHBOARD_PASSWORD", "").strip()
