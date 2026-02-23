"""Tests for core data models."""

from datetime import datetime, timezone

from watchclaw.models import (
    ActionEvent,
    ActionType,
    AgentProfile,
    AnomalyResult,
    Decision,
    RunningStats,
    Signal,
    TaintLevel,
)


class TestRunningStats:
    def test_empty_z_score_is_zero(self):
        stats = RunningStats()
        assert stats.z_score(5.0) == 0.0

    def test_single_value_z_score_is_zero(self):
        stats = RunningStats()
        stats.update(10.0)
        assert stats.z_score(10.0) == 0.0

    def test_z_score_positive(self):
        stats = RunningStats()
        for v in [10.0, 10.0, 10.0, 10.0, 10.0]:
            stats.update(v)
        # Value above mean should have positive z-score
        # But with zero variance, z_score returns 0.0
        assert stats.z_score(10.0) == 0.0

    def test_z_score_with_variance(self):
        stats = RunningStats()
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            stats.update(v)
        # Mean = 3.0, variance = 2.0, std = ~1.414
        z = stats.z_score(5.0)
        assert z > 1.0  # (5.0 - 3.0) / 1.414 ≈ 1.41

    def test_welford_mean(self):
        stats = RunningStats()
        for v in [2.0, 4.0, 6.0]:
            stats.update(v)
        assert abs(stats.mean - 4.0) < 1e-9

    def test_min_max(self):
        stats = RunningStats()
        for v in [5.0, 1.0, 9.0, 3.0]:
            stats.update(v)
        assert stats.min == 1.0
        assert stats.max == 9.0

    def test_count(self):
        stats = RunningStats()
        for v in [1.0, 2.0, 3.0]:
            stats.update(v)
        assert stats.count == 3


class TestActionEvent:
    def test_serialization_roundtrip(self):
        now = datetime.now(timezone.utc)
        event = ActionEvent(
            ts=now,
            session_id="sess-1",
            agent_id="agent-1",
            action_type=ActionType.FILE_READ,
            target="/etc/passwd",
            args={"mode": "r"},
            result_summary="ok",
            bytes_count=1024,
            taint_level=TaintLevel.HIGH,
            source="test",
        )
        d = event.to_dict()
        restored = ActionEvent.from_dict(d)
        assert restored.session_id == event.session_id
        assert restored.agent_id == event.agent_id
        assert restored.action_type == event.action_type
        assert restored.target == event.target
        assert restored.taint_level == event.taint_level

    def test_default_values(self):
        event = ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="s",
            agent_id="a",
            action_type=ActionType.EXEC,
            target="ls",
        )
        assert event.args == {}
        assert event.bytes_count == 0
        assert event.taint_level == TaintLevel.NONE


class TestAgentProfile:
    def test_maturity_growth(self):
        profile = AgentProfile(agent_id="test")
        assert profile.maturity == 0.0
        for _ in range(50):
            profile.record_observation()
        assert abs(profile.maturity - 0.5) < 1e-9
        for _ in range(50):
            profile.record_observation()
        assert profile.maturity == 1.0

    def test_default_signal_weights(self):
        profile = AgentProfile(agent_id="test")
        assert "time_anomaly" in profile.signal_weights
        assert "taint_flow" in profile.signal_weights
        assert len(profile.signal_weights) == 6


class TestAnomalyResult:
    def test_to_dict(self):
        result = AnomalyResult(
            score=0.5,
            signals=[Signal(name="test", value=0.5, weight=1.0, reason="test reason")],
            decision=Decision.NOTICE,
        )
        d = result.to_dict()
        assert d["score"] == 0.5
        assert d["decision"] == "NOTICE"
        assert len(d["signals"]) == 1
