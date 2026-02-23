"""Tests for AgentProfile behavior learning, cold-start blending, and scoring integration."""

from datetime import datetime, timedelta, timezone

from watchclaw.models import ActionEvent, ActionType, AgentProfile
from watchclaw.scorer import (
    DEFAULT_WEIGHTS,
    AnomalyScorer,
    get_effective_weight,
)
from watchclaw.taint import TaintTable


def _make_event(
    hour: int = 10,
    action_type: ActionType = ActionType.FILE_READ,
    target: str = "src/main.py",
    agent_id: str = "test-agent",
    args: dict | None = None,
) -> ActionEvent:
    ts = datetime(2025, 6, 15, hour, 30, 0, tzinfo=timezone.utc)
    return ActionEvent(
        ts=ts,
        session_id="test-session",
        agent_id=agent_id,
        action_type=action_type,
        target=target,
        args=args or {},
        source="test",
    )


class TestProfileLearning:
    """Profile should learn from observed events."""

    def test_hourly_activity_reflects_distribution(self):
        """After 50 events, hourly_activity raw counts should reflect distribution."""
        profile = AgentProfile(agent_id="learner")

        # Send 30 events at hour 10, 20 events at hour 14
        for _ in range(30):
            profile.update_profile(_make_event(hour=10))
        for _ in range(20):
            profile.update_profile(_make_event(hour=14))

        assert profile.observations == 50
        # Raw counts
        assert profile.hourly_activity[10] == 30.0
        assert profile.hourly_activity[14] == 20.0
        # get_hour_probability normalizes + dampens by maturity (0.5 at 50 obs)
        prob_10 = profile.get_hour_probability(10)
        prob_14 = profile.get_hour_probability(14)
        assert prob_10 > prob_14
        # raw_prob = 30/50 = 0.6, dampened by maturity 0.5 → 0.3
        assert abs(prob_10 - 0.3) < 0.01
        # raw_prob = 20/50 = 0.4, dampened by maturity 0.5 → 0.2
        assert abs(prob_14 - 0.2) < 0.01

    def test_maturity_reaches_one_at_100_observations(self):
        """Maturity should reach 1.0 after 100 observations."""
        profile = AgentProfile(agent_id="learner")
        for _ in range(100):
            profile.update_profile(_make_event())
        assert profile.maturity == 1.0

    def test_maturity_at_50_observations(self):
        """Maturity should be 0.5 after 50 observations."""
        profile = AgentProfile(agent_id="learner")
        for _ in range(50):
            profile.update_profile(_make_event())
        assert abs(profile.maturity - 0.5) < 1e-9

    def test_common_files_tracked(self):
        """File access should be tracked in common_files."""
        profile = AgentProfile(agent_id="learner")
        for _ in range(5):
            profile.update_profile(
                _make_event(action_type=ActionType.FILE_READ, target="src/main.py")
            )
        for _ in range(3):
            profile.update_profile(
                _make_event(action_type=ActionType.FILE_WRITE, target="src/utils.py")
            )
        # Also send an EXEC event — should NOT be in common_files
        profile.update_profile(
            _make_event(action_type=ActionType.EXEC, target="pytest")
        )

        assert profile.common_files["src/main.py"] == 5
        assert profile.common_files["src/utils.py"] == 3
        assert "pytest" not in profile.common_files

    def test_common_commands_tracked(self):
        """EXEC events should update common_commands."""
        profile = AgentProfile(agent_id="learner")
        for _ in range(4):
            profile.update_profile(
                _make_event(action_type=ActionType.EXEC, target="pytest tests/")
            )
        assert profile.common_commands["pytest tests/"] == 4

    def test_common_domains_tracked(self):
        """Domain access should be tracked in common_domains."""
        profile = AgentProfile(agent_id="learner")
        for _ in range(3):
            profile.update_profile(
                _make_event(
                    action_type=ActionType.WEB_FETCH,
                    target="https://api.github.com",
                    args={"domain": "api.github.com"},
                )
            )
        assert profile.common_domains["api.github.com"] == 3


class TestColdStartBlending:
    """New agents should use conservative default weights."""

    def test_fresh_agent_uses_default_weights(self):
        """Maturity=0 → 100% default weights."""
        profile = AgentProfile(agent_id="fresh")
        assert profile.maturity == 0.0

        for signal_name, default_w in DEFAULT_WEIGHTS.items():
            effective = get_effective_weight(profile, signal_name)
            assert abs(effective - default_w) < 1e-9, (
                f"{signal_name}: expected {default_w}, got {effective}"
            )

    def test_mature_agent_uses_personal_weights(self):
        """Maturity=1.0 → 100% personal weights."""
        profile = AgentProfile(agent_id="mature")
        # Manually set maturity to 1.0
        profile.maturity = 1.0
        profile.signal_weights["time_anomaly"] = 1.5

        effective = get_effective_weight(profile, "time_anomaly")
        assert abs(effective - 1.5) < 1e-9

    def test_half_maturity_blends_50_50(self):
        """Maturity=0.5 → 50% default + 50% personal."""
        profile = AgentProfile(agent_id="mid")
        profile.maturity = 0.5
        profile.signal_weights["time_anomaly"] = 1.0

        default_w = DEFAULT_WEIGHTS["time_anomaly"]  # 0.20
        personal_w = 1.0
        expected = default_w * 0.5 + personal_w * 0.5  # 0.10 + 0.50 = 0.60
        effective = get_effective_weight(profile, "time_anomaly")
        assert abs(effective - expected) < 1e-9

    def test_weight_blending_all_signals(self):
        """All signals should respect maturity-based blending."""
        profile = AgentProfile(agent_id="test")
        profile.maturity = 0.25  # 75% default, 25% personal

        for signal_name in DEFAULT_WEIGHTS:
            default_w = DEFAULT_WEIGHTS[signal_name]
            personal_w = profile.signal_weights[signal_name]
            expected = default_w * 0.75 + personal_w * 0.25
            effective = get_effective_weight(profile, signal_name)
            assert abs(effective - expected) < 1e-9, signal_name


class TestColdStartScoring:
    """New agents should score more conservatively than mature agents."""

    def test_new_agent_scores_more_conservatively(self):
        """A fresh agent and a mature agent seeing the same event should differ.

        A mature agent with learned hourly_activity and known files gets
        lower time_anomaly and resource_anomaly signal values.
        """
        taint = TaintTable()
        scorer = AnomalyScorer(taint_table=taint)

        now = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        scorer.on_user_message(ts=now - timedelta(seconds=5))  # Recent user msg

        event = _make_event(hour=10, target="src/main.py")

        # Fresh agent: cold-start dampened time_anomaly (~0.3), unknown files
        fresh_profile = AgentProfile(agent_id="fresh")
        fresh_result = scorer.score(event, fresh_profile, now=now)

        # Mature agent: has learned that hour 10 is active, and file is known
        mature_profile = AgentProfile(agent_id="mature")
        mature_profile.maturity = 1.0
        mature_profile.observations = 100
        # Raw counts: 60 events at hour 10, 40 at other hours
        mature_profile.hourly_activity[10] = 60.0
        mature_profile.hourly_activity[14] = 40.0
        mature_profile.common_files["src/main.py"] = 50  # Known file

        mature_result = scorer.score(event, mature_profile, now=now)

        # Mature agent should score lower because:
        # - time_anomaly: mature has learned hour 10 → signal=0.4 (with equal weights)
        #   vs fresh: cold-start dampened → signal=0.3 (with lower default weights)
        # - resource_anomaly: known file gets 0.5x vs unknown 1.5x
        # The weight normalization (6.0 for mature vs 1.0 for fresh) plus
        # the fresh agent's unknown file penalty keeps fresh > mature overall.
        assert mature_result.score < fresh_result.score

    def test_common_file_reduces_resource_anomaly(self):
        """A file in common_files should have lower resource_anomaly signal."""
        taint = TaintTable()
        scorer = AnomalyScorer(taint_table=taint)
        scorer.on_user_message()

        now = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        target = "config/settings.yaml"  # Moderate sensitivity (.yaml = 0.4)

        profile_unknown = AgentProfile(agent_id="unknown")
        profile_unknown.maturity = 1.0
        event = _make_event(hour=10, target=target)
        result_unknown = scorer.score(event, profile_unknown, now=now)

        profile_known = AgentProfile(agent_id="known")
        profile_known.maturity = 1.0
        profile_known.common_files[target] = 20
        result_known = scorer.score(event, profile_known, now=now)

        # Extract resource_anomaly signal values
        ra_unknown = next(s for s in result_unknown.signals if s.name == "resource_anomaly")
        ra_known = next(s for s in result_known.signals if s.name == "resource_anomaly")

        # Known file should have lower resource anomaly
        assert ra_known.value < ra_unknown.value


class TestProfileUpdateFromEngine:
    """Engine should update profiles via update_profile()."""

    def test_engine_updates_profile(self):
        """Processing events through engine should build profile."""
        from watchclaw.engine import WatchClawEngine

        engine = WatchClawEngine(config={"action_log": "/tmp/test-profile-action.log"})
        now = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)

        for i in range(10):
            event = ActionEvent(
                ts=now + timedelta(seconds=i),
                session_id="test",
                agent_id="melody",
                action_type=ActionType.FILE_READ,
                target="src/main.py",
                source="test",
            )
            engine.process_event(event)

        profile = engine.get_profile("melody")
        assert profile is not None
        assert profile.observations == 10
        assert profile.maturity == 0.1
        assert profile.hourly_activity[10] > 0.0
        assert "src/main.py" in profile.common_files
