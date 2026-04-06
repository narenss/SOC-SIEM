"""Unit tests for brute-force and after-hours correlation rules (mocked Graylog + DB)."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

from diy_siem.correlator import (
    BRUTE_FORCE_THRESHOLD,
    MITRE_AFTER_HOURS,
    MITRE_BRUTE_FORCE,
    run_after_hours_login_rule,
    run_auth_brute_force_rule,
)


def _graylog_search_payload(inner_messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Shape returned by Graylog universal relative search (see `messages_from_search`)."""
    return {
        "messages": [{"message": m} for m in inner_messages],
        "total_results": len(inner_messages),
    }


def _failed_msg(src_ip: str, n: int) -> dict[str, Any]:
    return {
        "message": f"diy-siem auth event=failed_login src_ip={src_ip} user=u{n}",
        "src_ip": src_ip,
        "event": "failed_login",
        "id": f"msg-{n}",
    }


def _success_msg(
    *,
    user: str,
    ts_iso: str,
    win_id: int | None = None,
) -> dict[str, Any]:
    m: dict[str, Any] = {
        "message": "diy-siem auth event=success_login",
        "user": user,
        "timestamp": ts_iso,
        "id": "succ-1",
    }
    if win_id is not None:
        m["win_event_id"] = str(win_id)
        m["message"] = f"diy-siem windows EventID={win_id}"
    return m


class BruteForceRuleTests(unittest.TestCase):
    def test_no_messages(self) -> None:
        with patch("diy_siem.correlator.search_relative", return_value=_graylog_search_payload([])), patch(
            "diy_siem.correlator.ollama_enabled",
            return_value=False,
        ):
            out = run_auth_brute_force_rule()
        self.assertFalse(out["fired"])
        self.assertEqual(out["reason"], "no_matching_messages")

    def test_below_threshold_no_alert(self) -> None:
        msgs = [_failed_msg("203.0.113.10", i) for i in range(BRUTE_FORCE_THRESHOLD - 1)]
        with patch(
            "diy_siem.correlator.search_relative",
            return_value=_graylog_search_payload(msgs),
        ), patch("diy_siem.correlator.ollama_enabled", return_value=False):
            out = run_auth_brute_force_rule()
        self.assertFalse(out["fired"])
        self.assertEqual(out["reason"], "below_threshold")
        self.assertEqual(out["threshold"], BRUTE_FORCE_THRESHOLD)

    def test_meets_threshold_inserts_t1110(self) -> None:
        msgs = [_failed_msg("203.0.113.10", i) for i in range(BRUTE_FORCE_THRESHOLD)]
        with patch(
            "diy_siem.correlator.search_relative",
            return_value=_graylog_search_payload(msgs),
        ), patch("diy_siem.correlator.db.count_recent_alerts", return_value=0), patch(
            "diy_siem.correlator.db.insert_alert",
            return_value=42,
        ) as ins, patch("diy_siem.correlator.ollama_enabled", return_value=False):
            out = run_auth_brute_force_rule()

        self.assertTrue(out["fired"])
        self.assertEqual(out["alert_id"], 42)
        self.assertEqual(out["mitre_technique"], MITRE_BRUTE_FORCE)
        self.assertEqual(out["bucket"], "ip:203.0.113.10")
        ins.assert_called_once()
        kw = ins.call_args.kwargs
        self.assertEqual(kw["rule_name"], "auth_brute_force:ip:203.0.113.10")
        self.assertEqual(kw["severity"], "high")
        self.assertEqual(kw["mitre_technique"], MITRE_BRUTE_FORCE)

    def test_deduplicated_when_recent_alert_exists(self) -> None:
        msgs = [_failed_msg("198.51.100.1", i) for i in range(BRUTE_FORCE_THRESHOLD)]
        with patch(
            "diy_siem.correlator.search_relative",
            return_value=_graylog_search_payload(msgs),
        ), patch("diy_siem.correlator.db.count_recent_alerts", return_value=1), patch(
            "diy_siem.correlator.db.insert_alert",
        ) as ins, patch("diy_siem.correlator.ollama_enabled", return_value=False):
            out = run_auth_brute_force_rule()

        self.assertFalse(out["fired"])
        self.assertEqual(out["reason"], "deduplicated")
        ins.assert_not_called()


class AfterHoursRuleTests(unittest.TestCase):
    def test_no_messages(self) -> None:
        with patch("diy_siem.correlator.search_relative", return_value=_graylog_search_payload([])), patch(
            "diy_siem.correlator.ollama_enabled",
            return_value=False,
        ):
            out = run_after_hours_login_rule()
        self.assertFalse(out["fired"])
        self.assertEqual(out["reason"], "no_after_hours_success_logins")

    def test_success_during_ist_business_hours_no_alert(self) -> None:
        # 04:30 UTC = 10:00 IST on 2024-06-15 — inside [08:00, 18:00)
        ts = datetime(2024, 6, 15, 4, 30, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        msgs = [_success_msg(user="alice", ts_iso=ts)]
        with patch(
            "diy_siem.correlator.search_relative",
            return_value=_graylog_search_payload(msgs),
        ), patch("diy_siem.correlator.db.insert_alert") as ins, patch(
            "diy_siem.correlator.ollama_enabled",
            return_value=False,
        ):
            out = run_after_hours_login_rule()
        self.assertFalse(out["fired"])
        self.assertEqual(out["reason"], "no_after_hours_success_logins")
        ins.assert_not_called()

    def test_success_outside_ist_business_hours_fires_t1078(self) -> None:
        # 13:00 UTC = 18:30 IST — outside (hour >= 18)
        ts = datetime(2024, 6, 15, 13, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        msgs = [_success_msg(user="bob", ts_iso=ts)]
        with patch(
            "diy_siem.correlator.search_relative",
            return_value=_graylog_search_payload(msgs),
        ), patch("diy_siem.correlator.db.count_recent_alerts", return_value=0), patch(
            "diy_siem.correlator.db.insert_alert",
            return_value=7,
        ) as ins, patch("diy_siem.correlator.ollama_enabled", return_value=False):
            out = run_after_hours_login_rule()

        self.assertTrue(out["fired"])
        self.assertEqual(out["alert_id"], 7)
        self.assertEqual(out["mitre_technique"], MITRE_AFTER_HOURS)
        self.assertEqual(out["user"], "bob")
        ins.assert_called_once()
        kw = ins.call_args.kwargs
        self.assertEqual(kw["rule_name"], "after_hours_login:bob")
        self.assertEqual(kw["mitre_technique"], MITRE_AFTER_HOURS)

    def test_windows_4624_outside_hours(self) -> None:
        ts = datetime(2024, 6, 15, 2, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        msgs = [_success_msg(user="svc", ts_iso=ts, win_id=4624)]
        with patch(
            "diy_siem.correlator.search_relative",
            return_value=_graylog_search_payload(msgs),
        ), patch("diy_siem.correlator.db.count_recent_alerts", return_value=0), patch(
            "diy_siem.correlator.db.insert_alert",
            return_value=1,
        ), patch("diy_siem.correlator.ollama_enabled", return_value=False):
            out = run_after_hours_login_rule()
        self.assertTrue(out["fired"])
        self.assertEqual(out["user"], "svc")

    def test_after_hours_deduplicated(self) -> None:
        ts = datetime(2024, 6, 15, 13, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        msgs = [_success_msg(user="carol", ts_iso=ts)]
        with patch(
            "diy_siem.correlator.search_relative",
            return_value=_graylog_search_payload(msgs),
        ), patch("diy_siem.correlator.db.count_recent_alerts", return_value=1), patch(
            "diy_siem.correlator.db.insert_alert",
        ) as ins, patch("diy_siem.correlator.ollama_enabled", return_value=False):
            out = run_after_hours_login_rule()
        self.assertFalse(out["fired"])
        self.assertEqual(out["reason"], "deduplicated")
        ins.assert_not_called()


if __name__ == "__main__":
    unittest.main()
