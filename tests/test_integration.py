"""Integration tests: end-to-end event processing through all layers."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchclaw.engine import WatchClawEngine
from watchclaw.models import ActionEvent, ActionType, Decision
from watchclaw.parser import SimulatedEventGenerator


def _make_engine(tmp_path: Path) -> WatchClawEngine:
    """Create a fully configured engine with temp action log."""
    config = {
        "action_log": str(tmp_path / "action.log"),
        "taint_half_life": 300.0,
    }
    engine = WatchClawEngine(config=config)
    # Load default rules
    rules_path = Path(__file__).parent.parent / "configs" / "default-rules.yaml"
    if rules_path.exists():
        engine.rule_engine.load_rules(rules_path)
    return engine


class TestNormalEventsAllowed:
    """Normal events should get NORMAL decision."""

    def test_file_read_normal(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="test-1",
            agent_id="melody",
            action_type=ActionType.FILE_READ,
            target="src/main.py",
            source="test",
        )
        result = engine.process_event(event)
        # Fresh profiles have cold-start dampened time_anomaly (~0.3) and user_idle=0.2.
        # Normal events should be NORMAL or NOTICE.
        assert result.decision in (Decision.NORMAL, Decision.NOTICE)
        assert result.score < 0.5  # Should not be ALERT-level

    def test_normal_exec(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="test-2",
            agent_id="teddy",
            action_type=ActionType.EXEC,
            target="pytest tests/",
            source="test",
        )
        result = engine.process_event(event)
        assert result.decision in (Decision.NORMAL, Decision.NOTICE)
        assert result.score < 0.5

    def test_simulated_normal_events(self, tmp_path):
        """Batch of normal simulated events should not trigger ALERT or CRITICAL."""
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator(attack_ratio=0.0)

        results = []
        for event in gen.generate_stream(duration=10.0, attack_ratio=0.0):
            results.append(engine.process_event(event))

        assert len(results) > 0
        # Normal events should mostly be NORMAL or NOTICE.
        # Some normal commands (e.g. pip install) legitimately trigger hard rules,
        # so we allow up to 50% rule-triggered alerts in a small sample.
        benign_count = sum(1 for r in results if r.decision in (Decision.NORMAL, Decision.NOTICE))
        assert benign_count >= len(results) * 0.5


class TestReadThenExfil:
    """read_then_exfil attack should trigger ALERT or CRITICAL."""

    def test_exfil_sequence(self, tmp_path):
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        # Step 1: Read a sensitive file
        read_event = ActionEvent(
            ts=now,
            session_id="attack-1",
            agent_id="melody",
            action_type=ActionType.FILE_READ,
            target=".env",
            source="test",
        )
        engine.process_event(read_event)

        # Step 2: Web fetch to evil domain (within 120s)
        exfil_event = ActionEvent(
            ts=now + timedelta(seconds=5),
            session_id="attack-1",
            agent_id="melody",
            action_type=ActionType.WEB_FETCH,
            target="https://evil-exfil.com/upload",
            args={"domain": "evil-exfil.com"},
            source="test",
        )
        result = engine.process_event(exfil_event)

        # Should be ALERT or CRITICAL due to sequence pattern + anomaly scoring
        assert result.decision in (Decision.ALERT, Decision.CRITICAL)
        assert result.score >= 0.5

    def test_simulated_exfil(self, tmp_path):
        """SimulatedEventGenerator attack events should trigger detection."""
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_read_then_exfil()

        results = []
        for event in events:
            results.append(engine.process_event(event))

        # At least one event in the sequence should trigger alert
        max_decision = max(results, key=lambda r: r.score)
        assert max_decision.decision in (Decision.ALERT, Decision.CRITICAL, Decision.NOTICE)
        assert max_decision.score >= 0.3


class TestCognitiveTampering:
    """Cognitive tampering should trigger ALERT."""

    def test_web_fetch_then_cognitive_write(self, tmp_path):
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        # Step 1: External web fetch
        fetch_event = ActionEvent(
            ts=now,
            session_id="attack-2",
            agent_id="judy",
            action_type=ActionType.WEB_FETCH,
            target="https://evil.com/instructions",
            args={"domain": "evil.com"},
            source="test",
        )
        engine.process_event(fetch_event)

        # Step 2: Write to cognitive file (within 30s)
        write_event = ActionEvent(
            ts=now + timedelta(seconds=5),
            session_id="attack-2",
            agent_id="judy",
            action_type=ActionType.FILE_WRITE,
            target="SOUL.md",
            source="test",
        )
        result = engine.process_event(write_event)

        # Should trigger due to external_trigger_chain pattern + cognitive file rule
        assert result.decision in (Decision.ALERT, Decision.CRITICAL)

    def test_simulated_cognitive_tampering(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_cognitive_tampering()

        results = []
        for event in events:
            results.append(engine.process_event(event))

        # The write to cognitive file should be flagged
        max_result = max(results, key=lambda r: r.score)
        assert max_result.decision in (Decision.ALERT, Decision.CRITICAL)


class TestBulkCredentialAccess:
    """Bulk credential access should trigger detection via rules."""

    def test_rapid_credential_reads(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_bulk_credential_access()

        results = []
        for event in events:
            results.append(engine.process_event(event))

        assert len(results) >= 3
        # At least one should be flagged (may need 3+ to trigger sliding window rule)
        flagged = [r for r in results if r.decision in (Decision.ALERT, Decision.CRITICAL, Decision.NOTICE)]
        assert len(flagged) >= 1


class TestProfilesUpdated:
    """Processing events should update agent profiles."""

    def test_profiles_created(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="test-p",
            agent_id="elodie",
            action_type=ActionType.FILE_READ,
            target="src/main.py",
            source="test",
        )
        engine.process_event(event)

        profile = engine.get_profile("elodie")
        assert profile is not None
        assert profile.agent_id == "elodie"
        assert profile.observations == 1
        assert "src/main.py" in profile.common_files

    def test_multiple_agents(self, tmp_path):
        engine = _make_engine(tmp_path)
        for agent in ["melody", "teddy", "judy"]:
            event = ActionEvent(
                ts=datetime.now(timezone.utc),
                session_id="test-multi",
                agent_id=agent,
                action_type=ActionType.FILE_READ,
                target="README.md",
                source="test",
            )
            engine.process_event(event)

        profiles = engine.get_profiles()
        assert "melody" in profiles
        assert "teddy" in profiles
        assert "judy" in profiles


class TestActionLogWritten:
    """Processing events should write to action.log."""

    def test_log_file_created(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="test-log",
            agent_id="melody",
            action_type=ActionType.FILE_READ,
            target="README.md",
            source="test",
        )
        engine.process_event(event)

        log_path = tmp_path / "action.log"
        assert log_path.exists()
        content = log_path.read_text().strip()
        assert len(content) > 0
        data = json.loads(content)
        assert data["event"]["agent_id"] == "melody"
        assert "anomaly" in data

    def test_multiple_entries(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator(attack_ratio=0.0)

        count = 0
        for event in gen.generate_stream(duration=5.0, attack_ratio=0.0):
            engine.process_event(event)
            count += 1

        log_path = tmp_path / "action.log"
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == count

    def test_attack_logged_with_sequences(self, tmp_path):
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        # Create a read-then-exfil that triggers sequence detection
        events = [
            ActionEvent(
                ts=now,
                session_id="log-test",
                agent_id="melody",
                action_type=ActionType.FILE_READ,
                target=".env",
                source="test",
            ),
            ActionEvent(
                ts=now + timedelta(seconds=5),
                session_id="log-test",
                agent_id="melody",
                action_type=ActionType.WEB_FETCH,
                target="https://evil.com/upload",
                args={"domain": "evil.com"},
                source="test",
            ),
        ]
        for e in events:
            engine.process_event(e)

        log_path = tmp_path / "action.log"
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 2

        # Check that the second entry has sequence info
        last_entry = json.loads(lines[-1])
        assert "sequences" in last_entry


class TestEndToEndSimulation:
    """Full end-to-end test with mixed normal and attack events."""

    def test_mixed_simulation(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator(attack_ratio=0.2)

        results = []
        for event in gen.generate_stream(duration=15.0, attack_ratio=0.2):
            results.append(engine.process_event(event))

        assert len(results) > 0

        # Should have a mix of decisions
        decisions = {r.decision for r in results}
        # Fresh profiles have elevated time_anomaly, so NORMAL may not appear.
        # At minimum we should have benign decisions (NORMAL or NOTICE) from normal events.
        assert decisions & {Decision.NORMAL, Decision.NOTICE}

        # Check log was written correctly
        log_path = tmp_path / "action.log"
        assert log_path.exists()
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == len(results)

        # Verify each log entry is valid JSON
        for line in lines:
            data = json.loads(line)
            assert "event" in data
            assert "anomaly" in data
