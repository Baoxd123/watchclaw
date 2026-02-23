"""Tests for anomaly scoring."""

from datetime import datetime, timezone

from watchclaw.models import ActionEvent, ActionType, AgentProfile, Decision
from watchclaw.scorer import AnomalyScorer
from watchclaw.taint import TaintTable


def _make_event(
    action_type: ActionType = ActionType.FILE_READ,
    target: str = "src/main.py",
    args: dict | None = None,
) -> ActionEvent:
    return ActionEvent(
        ts=datetime.now(timezone.utc),
        session_id="test",
        agent_id="test-agent",
        action_type=action_type,
        target=target,
        args=args or {},
        source="test",
    )


class TestAnomalyScorer:
    def test_normal_scenario_allows(self):
        """Normal activity during working hours should score low."""
        taint = TaintTable()
        scorer = AnomalyScorer(taint_table=taint)
        scorer.on_user_message()

        profile = AgentProfile(agent_id="test-agent")
        # Set current hour as active
        now = datetime.now(timezone.utc)
        profile.hourly_activity[now.hour] = 0.8
        # Mark target as known
        profile.common_files["src/main.py"] = 10

        event = _make_event(target="src/main.py")
        result = scorer.score(event, profile, now=now)

        assert result.score < 0.3
        assert result.decision == Decision.NORMAL

    def test_suspicious_scenario_alerts(self):
        """Unusual activity pattern should score higher."""
        taint = TaintTable()
        scorer = AnomalyScorer(taint_table=taint)
        # No recent user message → high idle score

        profile = AgentProfile(agent_id="test-agent")
        # No hour activity set → high time anomaly
        # Unknown sensitive file → high resource anomaly

        event = _make_event(
            action_type=ActionType.FILE_READ,
            target="/home/user/.env",
            args={"domain": "unknown-evil-site.com"},
        )
        now = datetime.now(timezone.utc)
        result = scorer.score(event, profile, now=now)

        # Should be elevated due to: time anomaly + idle + resource + destination
        assert result.score >= 0.3
        assert result.decision in (Decision.NOTICE, Decision.ALERT, Decision.CRITICAL)

    def test_six_signals_present(self):
        """All 6 signals should be present in result."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event()
        result = scorer.score(event, profile)

        signal_names = {s.name for s in result.signals}
        expected = {"time_anomaly", "user_idle", "rate_burst", "resource_anomaly",
                    "destination_anomaly", "taint_flow"}
        assert signal_names == expected

    def test_score_bounded_zero_to_one(self):
        """Score should always be between 0 and 1."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event()
        result = scorer.score(event, profile)

        assert 0.0 <= result.score <= 1.0
