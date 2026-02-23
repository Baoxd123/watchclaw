"""Tests for Discord alerter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from watchclaw.alerter import (
    COLOR_ALERT,
    COLOR_CRITICAL,
    COLOR_NOTICE,
    DiscordAlerter,
    _decision_color,
)
from watchclaw.models import (
    ActionEvent,
    ActionType,
    AnomalyResult,
    AuditVerdict,
    Decision,
    Signal,
    TaintLevel,
    Verdict,
)


def _make_event(**overrides) -> ActionEvent:
    defaults = dict(
        ts=datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        session_id="sess-1",
        agent_id="test-agent",
        action_type=ActionType.FILE_READ,
        target="/etc/passwd",
    )
    defaults.update(overrides)
    return ActionEvent(**defaults)


def _make_anomaly(decision: Decision = Decision.ALERT, score: float = 0.6) -> AnomalyResult:
    return AnomalyResult(
        score=score,
        signals=[
            Signal(name="resource_anomaly", value=0.8, weight=1.0, reason="sensitive file"),
            Signal(name="taint_flow", value=0.5, weight=1.0, reason="high taint"),
            Signal(name="time_anomaly", value=0.3, weight=1.0, reason="off-hours"),
        ],
        decision=decision,
    )


class TestDecisionColor:
    def test_alert_color(self):
        assert _decision_color(Decision.ALERT) == COLOR_ALERT

    def test_escalate_color(self):
        assert _decision_color(Decision.CRITICAL) == COLOR_CRITICAL

    def test_log_color(self):
        assert _decision_color(Decision.NOTICE) == COLOR_NOTICE

    def test_allow_gets_log_color(self):
        assert _decision_color(Decision.NORMAL) == COLOR_NOTICE


class TestAlertColorMapping:
    def test_alert_is_yellow(self):
        assert COLOR_ALERT == 0xFFAA00

    def test_escalate_is_red(self):
        assert COLOR_CRITICAL == 0xFF0000

    def test_log_is_gray(self):
        assert COLOR_NOTICE == 0x808080


class TestDiscordEmbedFormat:
    def test_embed_contains_required_fields(self):
        """Verify Discord embed payload has title, color, and all key fields."""
        alerter = DiscordAlerter(webhook_url="https://discord.com/api/webhooks/test/token")
        event = _make_event()
        anomaly = _make_anomaly(Decision.ALERT, 0.65)

        captured = {}

        def mock_urlopen(req, **kwargs):
            captured["payload"] = json.loads(req.data.decode("utf-8"))
            resp = MagicMock()
            resp.status = 204
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("watchclaw.alerter.urllib.request.urlopen", side_effect=mock_urlopen):
            result = alerter.send(event, anomaly)

        assert result is True
        payload = captured["payload"]
        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert "ALERT" in embed["title"]
        assert embed["color"] == COLOR_ALERT
        field_names = [f["name"] for f in embed["fields"]]
        assert "Agent ID" in field_names
        assert "Anomaly Score" in field_names
        assert "Target" in field_names
        assert "Top 3 Signals" in field_names

    def test_escalate_embed_includes_verdict(self):
        """Verify CRITICAL embed includes auditor verdict."""
        alerter = DiscordAlerter(webhook_url="https://discord.com/api/webhooks/test/token")
        event = _make_event()
        anomaly = _make_anomaly(Decision.CRITICAL, 0.85)
        verdict = AuditVerdict(
            verdict=Verdict.MALICIOUS,
            confidence=0.8,
            reason="High-confidence exfiltration attempt",
        )

        captured = {}

        def mock_urlopen(req, **kwargs):
            captured["payload"] = json.loads(req.data.decode("utf-8"))
            resp = MagicMock()
            resp.status = 204
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("watchclaw.alerter.urllib.request.urlopen", side_effect=mock_urlopen):
            result = alerter.send(event, anomaly, verdict)

        assert result is True
        embed = captured["payload"]["embeds"][0]
        assert embed["color"] == COLOR_CRITICAL
        field_names = [f["name"] for f in embed["fields"]]
        assert "Auditor Verdict" in field_names

    def test_no_webhook_url_returns_false(self):
        alerter = DiscordAlerter(webhook_url=None)
        event = _make_event()
        anomaly = _make_anomaly()
        assert alerter.send(event, anomaly) is False

    def test_network_error_returns_false(self):
        alerter = DiscordAlerter(webhook_url="https://discord.com/api/webhooks/test/token")
        event = _make_event()
        anomaly = _make_anomaly()

        with patch("watchclaw.alerter.urllib.request.urlopen", side_effect=ConnectionError("fail")):
            assert alerter.send(event, anomaly) is False
