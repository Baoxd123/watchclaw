"""Boundary condition tests: edge cases, error handling, and performance.

Tests cover:
- Empty event lists
- None value fields
- Super-long target strings (>10000 chars)
- Non-UTF-8 content in feature extraction
- 100+ simultaneous taint entries performance
- Future timestamps
- Duplicate events (same ts + agent + target)
- agent_id with special characters
- Engine process_event exception safety
- Server query param validation
- Parser malformed log lines
- Alerter graceful degradation
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from watchclaw.engine import WatchClawEngine
from watchclaw.features import extract_content_features, shannon_entropy
from watchclaw.models import (
    ActionEvent,
    ActionType,
    AgentProfile,
    AnomalyResult,
    Decision,
    RunningStats,
    TaintLevel,
)
from watchclaw.parser import OpenClawLogParser, SimulatedEventGenerator
from watchclaw.rules import RuleEngine
from watchclaw.scorer import AnomalyScorer
from watchclaw.sequence import SequenceDetector
from watchclaw.server import _build_profiles, _build_stats, _read_action_log
from watchclaw.taint import TaintTable, compute_file_sensitivity
from watchclaw.alerter import DiscordAlerter


def _make_engine(tmp_path: Path) -> WatchClawEngine:
    config = {
        "action_log": str(tmp_path / "action.log"),
        "taint_half_life": 300.0,
    }
    engine = WatchClawEngine(config=config)
    rules_path = Path(__file__).parent.parent / "configs" / "default-rules.yaml"
    if rules_path.exists():
        engine.rule_engine.load_rules(rules_path)
    return engine


def _make_event(
    agent_id: str = "test-agent",
    target: str = "src/main.py",
    action_type: ActionType = ActionType.FILE_READ,
    ts: datetime | None = None,
    **kwargs,
) -> ActionEvent:
    return ActionEvent(
        ts=ts or datetime.now(timezone.utc),
        session_id="test-session",
        agent_id=agent_id,
        action_type=action_type,
        target=target,
        source="test",
        **kwargs,
    )


# ============================================================
# 1. Empty Event List Processing
# ============================================================

class TestEmptyEventList:
    """Engine and components handle empty event lists gracefully."""

    def test_engine_no_events_processed(self, tmp_path):
        """Engine with no events should have no profiles, empty logs."""
        engine = _make_engine(tmp_path)
        assert engine.get_profiles() == {}
        assert engine.get_profile("nonexistent") is None

    def test_sequence_detector_empty_window(self):
        """SequenceDetector with empty window returns no matches."""
        detector = SequenceDetector()
        # Directly test internal check methods with empty window
        assert detector._check_read_then_exfil() is None
        assert detector._check_config_then_escalate() is None
        assert detector._check_external_trigger_chain() is None

    def test_taint_table_aggregate_empty(self):
        """TaintTable with no entries returns 0.0 aggregate."""
        table = TaintTable()
        assert table.aggregate_taint() == 0.0
        assert table.get_entries() == []

    def test_rule_engine_no_rules(self):
        """RuleEngine with no rules returns empty matches."""
        engine = RuleEngine()
        event = _make_event()
        assert engine.evaluate(event) == []

    def test_empty_action_log_server(self, tmp_path):
        """Server functions handle empty/nonexistent log files."""
        nonexistent = tmp_path / "nonexistent.log"
        assert _read_action_log(nonexistent) == []
        assert _build_profiles(nonexistent) == []
        stats = _build_stats(nonexistent)
        assert stats["total"] == 0

    def test_empty_log_file_server(self, tmp_path):
        """Server functions handle an empty log file (0 bytes)."""
        empty_log = tmp_path / "empty.log"
        empty_log.write_text("")
        assert _read_action_log(empty_log) == []
        assert _build_profiles(empty_log) == []
        stats = _build_stats(empty_log)
        assert stats["total"] == 0

    def test_whitespace_only_log_file(self, tmp_path):
        """Server functions handle a whitespace-only log file."""
        ws_log = tmp_path / "ws.log"
        ws_log.write_text("   \n  \n\n  ")
        assert _read_action_log(ws_log) == []
        assert _build_profiles(ws_log) == []


# ============================================================
# 2. None Value Field Handling
# ============================================================

class TestNoneValueFields:
    """Components handle None and missing values in fields."""

    def test_event_empty_target(self, tmp_path):
        """Engine handles events with empty target string."""
        engine = _make_engine(tmp_path)
        event = _make_event(target="")
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)
        assert result.decision in Decision

    def test_event_empty_agent_id(self, tmp_path):
        """Engine handles events with empty agent_id."""
        engine = _make_engine(tmp_path)
        event = _make_event(agent_id="")
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)

    def test_event_empty_args(self, tmp_path):
        """Engine handles events with empty args dict."""
        engine = _make_engine(tmp_path)
        event = _make_event(args={})
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)

    def test_taint_on_empty_target(self):
        """Taint table handles empty target string."""
        table = TaintTable()
        event = _make_event(target="", action_type=ActionType.FILE_READ)
        table.on_action(event)  # Should not crash
        # Empty target has low sensitivity, no entry should be added
        assert table.aggregate_taint() == 0.0

    def test_compute_sensitivity_empty_path(self):
        """compute_file_sensitivity handles empty string."""
        score = compute_file_sensitivity("")
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_scorer_no_domain_in_args(self):
        """Scorer handles event with no domain key in args."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event(action_type=ActionType.WEB_FETCH, args={})
        result = scorer.score(event, profile)
        assert isinstance(result, AnomalyResult)

    def test_feature_extraction_empty_content(self):
        """Feature extraction on empty content."""
        features = extract_content_features("", "")
        assert features["size_bytes"] == 0
        assert features["entropy"] == 0.0
        assert features["api_key_patterns"] == 0

    def test_feature_extraction_empty_bytes(self):
        """Feature extraction on empty bytes."""
        features = extract_content_features(b"", "test.py")
        assert features["size_bytes"] == 0
        assert features["entropy"] == 0.0


# ============================================================
# 3. Super-Long Target Strings (>10000 chars)
# ============================================================

class TestLongTargetStrings:
    """Engine handles extremely long target strings."""

    def test_long_target_process_event(self, tmp_path):
        """Engine processes events with >10000 char target without crashing."""
        engine = _make_engine(tmp_path)
        long_target = "x" * 15000
        event = _make_event(target=long_target)
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)

    def test_long_target_rule_matching(self):
        """Rules evaluate correctly on very long target strings."""
        engine = RuleEngine()
        rules_path = Path(__file__).parent.parent / "configs" / "default-rules.yaml"
        if rules_path.exists():
            engine.load_rules(rules_path)
        long_target = "a/" * 5000 + ".env"
        event = _make_event(target=long_target)
        # Should not crash; may or may not match
        matches = engine.evaluate(event)
        assert isinstance(matches, list)

    def test_long_target_taint(self):
        """Taint table handles long target paths."""
        table = TaintTable()
        long_target = "/very/deep/" * 1000 + ".env"
        event = _make_event(target=long_target, action_type=ActionType.FILE_READ)
        table.on_action(event)
        # .env file should still be detected as sensitive
        score = table.aggregate_taint()
        assert score > 0

    def test_long_target_sequence(self):
        """Sequence detector handles long target strings."""
        detector = SequenceDetector()
        now = datetime.now(timezone.utc)
        long_target = "A" * 15000
        event = _make_event(target=long_target, ts=now)
        matches = detector.add_event(event)
        assert isinstance(matches, list)

    def test_long_target_feature_extraction(self):
        """Feature extraction on very long content."""
        long_content = "API_KEY=sk-test-" + "x" * 10000 + "\n" * 100
        features = extract_content_features(long_content, "test.env")
        assert features["size_bytes"] > 10000
        assert features["api_key_patterns"] >= 1

    def test_long_target_alerter(self):
        """Alerter builds embed with truncated long target."""
        alerter = DiscordAlerter(webhook_url=None)
        event = _make_event(target="x" * 15000)
        anomaly = AnomalyResult(score=0.8, signals=[], decision=Decision.ALERT)
        embed = alerter._build_embed(event, anomaly)
        # Target field should be truncated to 200 chars
        target_field = next(f for f in embed["fields"] if f["name"] == "Target")
        assert len(target_field["value"]) <= 200


# ============================================================
# 4. Non-UTF-8 Content Feature Extraction
# ============================================================

class TestNonUtf8Content:
    """Feature extraction handles non-UTF-8 binary content."""

    def test_binary_content_bytes(self):
        """Feature extraction on raw binary bytes (non-UTF-8)."""
        binary = bytes(range(256)) * 10
        features = extract_content_features(binary, "data.bin")
        assert features["size_bytes"] == 2560
        assert features["entropy"] > 0
        assert isinstance(features["api_key_patterns"], int)

    def test_invalid_utf8_sequences(self):
        """Feature extraction on deliberately invalid UTF-8."""
        invalid = b"\xff\xfe\x80\x81\xc0\xc1\xf5\xf6\xf7"
        features = extract_content_features(invalid, "corrupted.dat")
        assert features["size_bytes"] == len(invalid)
        assert isinstance(features["entropy"], float)

    def test_mixed_utf8_binary(self):
        """Feature extraction on mixed UTF-8 text with binary segments."""
        # API key pattern requires 20+ word chars after '='
        content = b"api_key=abcdefghijklmnopqrstuvwxyz\x00\xff\xfe" + b"\x80" * 100 + b"\npassword=secret"
        features = extract_content_features(content, ".env")
        assert features["api_key_patterns"] >= 1
        assert features["password_patterns"] >= 1

    def test_entropy_on_binary(self):
        """Shannon entropy works correctly on full byte range."""
        # All same bytes → entropy should be 0
        same_bytes = b"\x00" * 100
        assert shannon_entropy(same_bytes) == 0.0

        # All unique bytes (256) → max entropy ~8.0
        all_bytes = bytes(range(256))
        ent = shannon_entropy(all_bytes)
        assert 7.9 <= ent <= 8.0

    def test_null_bytes_content(self):
        """Feature extraction on content full of null bytes."""
        null_content = b"\x00" * 1000
        features = extract_content_features(null_content, "zeros.bin")
        assert features["size_bytes"] == 1000
        assert features["entropy"] == 0.0


# ============================================================
# 5. 100+ Taint Entries Performance
# ============================================================

class TestManyTaintEntries:
    """Performance with many simultaneous taint entries."""

    def test_100_taint_entries_performance(self):
        """100+ taint entries should aggregate quickly (<1 second)."""
        table = TaintTable(half_life=300.0)
        now = datetime.now(timezone.utc)

        # Create 150 taint entries from different sensitive files
        for i in range(150):
            event = _make_event(
                target=f"/secrets/key_{i}.env",
                action_type=ActionType.FILE_READ,
                ts=now - timedelta(seconds=i),
            )
            table.on_action(event)

        assert len(table.get_entries()) == 150

        # Aggregate should complete quickly
        start = time.monotonic()
        score = table.aggregate_taint(now)
        elapsed = time.monotonic() - start

        assert elapsed < 1.0  # Should be much faster than 1s
        assert score > 0.0

    def test_500_entries_still_fast(self):
        """Even with 500 entries, aggregation should be fast."""
        table = TaintTable(half_life=300.0)
        now = datetime.now(timezone.utc)

        for i in range(500):
            event = _make_event(
                target=f"/secrets/file_{i}.key",
                action_type=ActionType.FILE_READ,
                ts=now - timedelta(seconds=i * 0.5),
            )
            table.on_action(event)

        start = time.monotonic()
        score = table.aggregate_taint(now)
        elapsed = time.monotonic() - start

        assert elapsed < 1.0
        assert score > 0.0

    def test_many_entries_engine_performance(self, tmp_path):
        """Processing 100+ events through the full engine should be fast."""
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        start = time.monotonic()
        for i in range(120):
            event = _make_event(
                agent_id="perf-agent",
                target=f"file_{i}.py",
                action_type=ActionType.FILE_READ,
                ts=now + timedelta(seconds=i),
            )
            engine.process_event(event)
        elapsed = time.monotonic() - start

        assert elapsed < 5.0  # 120 events in under 5 seconds
        profile = engine.get_profile("perf-agent")
        assert profile.observations == 120


# ============================================================
# 6. Future Timestamps
# ============================================================

class TestFutureTimestamps:
    """Engine handles events with timestamps in the future."""

    def test_future_event_processed(self, tmp_path):
        """Events with future timestamps should still be processed."""
        engine = _make_engine(tmp_path)
        future_ts = datetime.now(timezone.utc) + timedelta(days=365)
        event = _make_event(ts=future_ts)
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)
        assert result.decision in Decision

    def test_future_taint_decay(self):
        """Taint decay works correctly with future timestamps."""
        table = TaintTable(half_life=300.0)
        now = datetime.now(timezone.utc)
        future = now + timedelta(hours=1)

        event = _make_event(
            target=".env",
            action_type=ActionType.FILE_READ,
            ts=now,
        )
        table.on_action(event)

        # At creation time, taint should be high
        score_now = table.aggregate_taint(now)
        assert score_now > 0.5

        # 1 hour later, taint should have decayed significantly
        score_future = table.aggregate_taint(future)
        assert score_future < score_now
        assert score_future < 0.01  # Heavily decayed after 3600s with 300s half-life

    def test_future_timestamp_sequence(self):
        """Sequence detection with future timestamps."""
        detector = SequenceDetector()
        future = datetime.now(timezone.utc) + timedelta(days=30)

        # Read sensitive file in the future
        event1 = _make_event(
            target=".env",
            action_type=ActionType.FILE_READ,
            ts=future,
        )
        detector.add_event(event1)

        # Exfil shortly after
        event2 = _make_event(
            target="https://evil.com/upload",
            action_type=ActionType.WEB_FETCH,
            ts=future + timedelta(seconds=10),
            args={"domain": "evil.com"},
        )
        matches = detector.add_event(event2)
        # Should still detect the read_then_exfil pattern
        assert any(m.pattern_name == "read_then_exfil" for m in matches)

    def test_scorer_future_time_anomaly(self):
        """Scorer handles future timestamps without crashing."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="future-agent")
        future = datetime.now(timezone.utc) + timedelta(days=365)
        event = _make_event(ts=future)
        result = scorer.score(event, profile, now=future)
        assert 0.0 <= result.score <= 1.0


# ============================================================
# 7. Duplicate Events (same ts + agent + target)
# ============================================================

class TestDuplicateEvents:
    """Engine handles duplicate events correctly."""

    def test_duplicate_events_both_processed(self, tmp_path):
        """Duplicate events should both be processed (no dedup)."""
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)
        event = _make_event(agent_id="dup-agent", target="src/main.py", ts=now)

        result1 = engine.process_event(event)
        result2 = engine.process_event(event)

        assert isinstance(result1, AnomalyResult)
        assert isinstance(result2, AnomalyResult)

        # Profile should have 2 observations
        profile = engine.get_profile("dup-agent")
        assert profile.observations == 2

    def test_duplicate_events_logged_separately(self, tmp_path):
        """Each duplicate event gets its own log entry."""
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)
        event = _make_event(agent_id="dup-agent", target="src/main.py", ts=now)

        engine.process_event(event)
        engine.process_event(event)

        log_path = tmp_path / "action.log"
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_duplicate_taint_entries_overwrite(self):
        """Duplicate taint entries for same target overwrite (latest wins)."""
        table = TaintTable()
        now = datetime.now(timezone.utc)
        later = now + timedelta(seconds=60)

        event1 = _make_event(target=".env", action_type=ActionType.FILE_READ, ts=now)
        event2 = _make_event(target=".env", action_type=ActionType.FILE_READ, ts=later)

        table.on_action(event1)
        table.on_action(event2)

        # Should still be 1 entry (overwritten), not 2
        entries = table.get_entries()
        assert len(entries) == 1
        assert entries[0].timestamp == later

    def test_many_duplicates_performance(self, tmp_path):
        """Processing many identical events should not degrade performance."""
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)
        event = _make_event(agent_id="dup-perf", target="main.py", ts=now)

        start = time.monotonic()
        for _ in range(100):
            engine.process_event(event)
        elapsed = time.monotonic() - start

        assert elapsed < 5.0


# ============================================================
# 8. Agent ID with Special Characters
# ============================================================

class TestSpecialCharAgentId:
    """Engine handles agent_id with special characters."""

    def test_agent_id_with_spaces(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = _make_event(agent_id="agent with spaces")
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)
        profile = engine.get_profile("agent with spaces")
        assert profile is not None

    def test_agent_id_with_unicode(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = _make_event(agent_id="agent-日本語-тест")
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)
        profile = engine.get_profile("agent-日本語-тест")
        assert profile.observations == 1

    def test_agent_id_with_special_chars(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = _make_event(agent_id="agent@host:8080/path?q=1&x=2")
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)

    def test_agent_id_with_newlines(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = _make_event(agent_id="agent\nwith\nnewlines")
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)

    def test_agent_id_with_null_char(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = _make_event(agent_id="agent\x00null")
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)

    def test_agent_id_very_long(self, tmp_path):
        engine = _make_engine(tmp_path)
        event = _make_event(agent_id="a" * 5000)
        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)

    def test_agent_id_logged_correctly(self, tmp_path):
        """Special char agent_id is preserved in JSON log."""
        engine = _make_engine(tmp_path)
        agent_id = "test-agent-ñ-日本"
        event = _make_event(agent_id=agent_id)
        engine.process_event(event)

        log_path = tmp_path / "action.log"
        data = json.loads(log_path.read_text().strip())
        assert data["event"]["agent_id"] == agent_id


# ============================================================
# 9. Engine Exception Safety (Error Handling)
# ============================================================

class TestEngineExceptionSafety:
    """process_event catches exceptions and returns safe defaults."""

    def test_bad_rule_engine_doesnt_crash(self, tmp_path):
        """If rule evaluation throws, engine still returns a result."""
        engine = _make_engine(tmp_path)
        event = _make_event()

        # Monkey-patch rule engine to raise
        original = engine.rule_engine.evaluate
        def bad_evaluate(_event):
            raise RuntimeError("Rule engine exploded")
        engine.rule_engine.evaluate = bad_evaluate

        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)
        assert result.decision == Decision.NOTICE  # Safe fallback
        engine.rule_engine.evaluate = original

    def test_bad_scorer_doesnt_crash(self, tmp_path):
        """If scorer throws, engine still returns a result."""
        engine = _make_engine(tmp_path)
        event = _make_event()

        original = engine.scorer.score
        def bad_score(_event, _profile, **kwargs):
            raise ValueError("Scorer exploded")
        engine.scorer.score = bad_score

        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)
        assert result.decision == Decision.NOTICE
        engine.scorer.score = original

    def test_bad_sequence_detector_doesnt_crash(self, tmp_path):
        """If sequence detector throws, engine still returns a result."""
        engine = _make_engine(tmp_path)
        event = _make_event()

        original = engine.sequence_detector.add_event
        def bad_add(_event):
            raise TypeError("Sequence detector exploded")
        engine.sequence_detector.add_event = bad_add

        result = engine.process_event(event)
        assert isinstance(result, AnomalyResult)
        assert result.decision == Decision.NOTICE
        engine.sequence_detector.add_event = original

    def test_engine_continues_after_error(self, tmp_path):
        """After an error on one event, engine can still process subsequent events."""
        engine = _make_engine(tmp_path)

        # Process a bad event (by breaking scorer temporarily)
        original = engine.scorer.score
        def bad_score(_event, _profile, **kwargs):
            raise RuntimeError("boom")
        engine.scorer.score = bad_score
        result1 = engine.process_event(_make_event())
        assert result1.decision == Decision.NOTICE  # Safe fallback

        # Restore and process a good event
        engine.scorer.score = original
        result2 = engine.process_event(_make_event(agent_id="good-agent"))
        assert isinstance(result2, AnomalyResult)
        assert result2.decision in Decision


# ============================================================
# 10. Parser Malformed Log Lines
# ============================================================

class TestParserMalformedLines:
    """Parser gracefully skips malformed log lines."""

    def test_invalid_json_lines(self, tmp_path):
        """Parser skips lines that are not valid JSON."""
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "not json at all\n"
            "{broken json\n"
            '{"0": "valid", "time": "2024-01-01T00:00:00Z"}\n'
        )
        parser = OpenClawLogParser(log_dir=str(tmp_path))
        events = list(parser.parse_file(log_file))
        # Should not crash, valid lines may or may not produce events
        assert isinstance(events, list)

    def test_missing_timestamp(self, tmp_path):
        """Parser skips entries without timestamps."""
        log_file = tmp_path / "test.log"
        log_file.write_text(
            '{"0": "some message", "1": "another"}\n'
        )
        parser = OpenClawLogParser(log_dir=str(tmp_path))
        events = list(parser.parse_file(log_file))
        assert events == []

    def test_invalid_timestamp_format(self, tmp_path):
        """Parser skips entries with unparseable timestamps."""
        log_file = tmp_path / "test.log"
        log_file.write_text(
            '{"0": "msg", "time": "not-a-date"}\n'
        )
        parser = OpenClawLogParser(log_dir=str(tmp_path))
        events = list(parser.parse_file(log_file))
        assert events == []

    def test_empty_log_file(self, tmp_path):
        """Parser handles empty log file."""
        log_file = tmp_path / "test.log"
        log_file.write_text("")
        parser = OpenClawLogParser(log_dir=str(tmp_path))
        events = list(parser.parse_file(log_file))
        assert events == []

    def test_nonexistent_log_file(self, tmp_path):
        """Parser handles nonexistent file."""
        parser = OpenClawLogParser(log_dir=str(tmp_path))
        events = list(parser.parse_file(tmp_path / "nonexistent.log"))
        assert events == []

    def test_binary_content_in_fields(self, tmp_path):
        """Parser handles non-string field values."""
        log_file = tmp_path / "test.log"
        log_file.write_text(
            '{"0": 12345, "1": null, "time": "2024-01-01T00:00:00Z"}\n'
            '{"0": {"nested": true}, "1": [1,2,3], "time": "2024-01-01T00:00:00Z"}\n'
        )
        parser = OpenClawLogParser(log_dir=str(tmp_path))
        events = list(parser.parse_file(log_file))
        # Should not crash; entries may not produce events but should be handled
        assert isinstance(events, list)


# ============================================================
# 11. Server Error Handling
# ============================================================

class TestServerErrorHandling:
    """Server-side functions handle edge cases."""

    def test_malformed_json_in_log(self, tmp_path):
        """_read_action_log skips malformed JSON lines."""
        log_file = tmp_path / "action.log"
        log_file.write_text(
            '{"event": {"agent_id": "a"}, "anomaly": {"decision": "NORMAL", "score": 0.1}}\n'
            'not json\n'
            '{"event": {"agent_id": "b"}, "anomaly": {"decision": "ALERT", "score": 0.6}}\n'
        )
        entries = _read_action_log(log_file)
        assert len(entries) == 2

    def test_build_profiles_with_missing_fields(self, tmp_path):
        """_build_profiles handles entries with missing fields."""
        log_file = tmp_path / "action.log"
        log_file.write_text(
            '{"event": {"agent_id": "test"}, "anomaly": {"decision": "NORMAL", "score": 0.1}}\n'
            '{"incomplete": true}\n'
        )
        profiles = _build_profiles(log_file)
        assert len(profiles) == 1
        assert profiles[0]["agent_id"] == "test"

    def test_build_stats_with_corrupt_data(self, tmp_path):
        """_build_stats handles corrupt JSON entries."""
        log_file = tmp_path / "action.log"
        log_file.write_text(
            '{"event": {"agent_id": "a"}, "anomaly": {"decision": "NORMAL"}, "rules": []}\n'
            'corrupt line\n'
        )
        stats = _build_stats(log_file)
        assert stats["total"] == 1
        assert stats["normals"] == 1


# ============================================================
# 12. Alerter Graceful Degradation
# ============================================================

class TestAlerterGracefulDegradation:
    """Alerter handles failures gracefully."""

    def test_no_webhook_returns_false(self):
        """Alerter with no webhook URL returns False."""
        alerter = DiscordAlerter(webhook_url=None)
        event = _make_event()
        anomaly = AnomalyResult(score=0.8, signals=[], decision=Decision.ALERT)
        assert alerter.send(event, anomaly) is False

    def test_empty_webhook_returns_false(self):
        """Alerter with empty webhook URL returns False."""
        alerter = DiscordAlerter(webhook_url="")
        event = _make_event()
        anomaly = AnomalyResult(score=0.8, signals=[], decision=Decision.ALERT)
        assert alerter.send(event, anomaly) is False

    def test_invalid_webhook_url_returns_false(self):
        """Alerter with invalid URL returns False gracefully."""
        alerter = DiscordAlerter(webhook_url="http://localhost:99999/nonexistent")
        event = _make_event()
        anomaly = AnomalyResult(score=0.8, signals=[], decision=Decision.ALERT)
        # Should catch the connection error and return False
        assert alerter.send(event, anomaly) is False

    def test_alerter_embed_with_no_signals(self):
        """Alerter builds embed even with empty signals list."""
        alerter = DiscordAlerter(webhook_url=None)
        event = _make_event()
        anomaly = AnomalyResult(score=0.5, signals=[], decision=Decision.ALERT)
        embed = alerter._build_embed(event, anomaly)
        assert "fields" in embed
        signal_field = next(f for f in embed["fields"] if f["name"] == "Top 3 Signals")
        assert signal_field["value"] == "None"


# ============================================================
# 13. Additional Edge Cases
# ============================================================

class TestRunningStatsEdgeCases:
    """RunningStats handles edge cases."""

    def test_z_score_zero_variance(self):
        """z_score with zero variance returns 0.0."""
        stats = RunningStats()
        # All same values → variance = 0
        for _ in range(10):
            stats.update(5.0)
        assert stats.z_score(5.0) == 0.0

    def test_z_score_single_value(self):
        """z_score with single observation returns 0.0."""
        stats = RunningStats()
        stats.update(1.0)
        assert stats.z_score(1.0) == 0.0

    def test_z_score_empty(self):
        """z_score with no observations returns 0.0."""
        stats = RunningStats()
        assert stats.z_score(1.0) == 0.0


class TestProfileMaturityEdgeCases:
    """Agent profile maturity edge cases."""

    def test_hour_probability_no_activity(self):
        """Hour probability with no activity returns 0.0."""
        profile = AgentProfile(agent_id="test")
        assert profile.get_hour_probability(12) == 0.0

    def test_maturity_clamp(self):
        """Maturity never exceeds 1.0."""
        profile = AgentProfile(agent_id="test")
        for _ in range(500):
            profile.record_observation()
        assert profile.maturity == 1.0

    def test_feedback_weight_clamp(self):
        """Signal weights clamped to [0.1, 2.0] on feedback."""
        profile = AgentProfile(agent_id="test")
        # Many false positives should lower weight but not below 0.1
        for _ in range(100):
            profile.on_user_feedback("alert-1", True, ["time_anomaly"])
        assert profile.signal_weights["time_anomaly"] >= 0.1

        # Many confirmed threats should raise weight but not above 2.0
        for _ in range(100):
            profile.on_user_feedback("alert-2", False, ["time_anomaly"])
        assert profile.signal_weights["time_anomaly"] <= 2.0


class TestTaintEdgeCases:
    """Taint table edge cases."""

    def test_taint_decay_very_old_entry(self):
        """Very old taint entries decay to essentially zero."""
        table = TaintTable(half_life=300.0)
        old_time = datetime.now(timezone.utc) - timedelta(days=365)
        event = _make_event(target=".env", action_type=ActionType.FILE_READ, ts=old_time)
        table.on_action(event)

        now = datetime.now(timezone.utc)
        score = table.aggregate_taint(now)
        assert score < 1e-10  # Essentially zero

    def test_sanitize_nonexistent_target(self):
        """Sanitizing a non-existent target doesn't crash."""
        table = TaintTable()
        table.on_user_message(target="/nonexistent/file")
        assert table.aggregate_taint() == 0.0

    def test_concurrent_sanitize_and_aggregate(self):
        """Sanitization + aggregate in sequence works correctly."""
        table = TaintTable()
        now = datetime.now(timezone.utc)
        event = _make_event(target=".env", action_type=ActionType.FILE_READ, ts=now)
        table.on_action(event)

        # Before sanitize
        score_before = table.aggregate_taint(now)
        assert score_before > 0

        # Sanitize
        table.on_user_message(target=".env")

        # After sanitize
        score_after = table.aggregate_taint(now)
        assert score_after == 0.0


class TestSequenceDetectorEdgeCases:
    """Sequence detector edge cases."""

    def test_window_overflow(self):
        """Window overflow (>50 events) doesn't crash."""
        detector = SequenceDetector(window_size=50)
        now = datetime.now(timezone.utc)
        for i in range(100):
            event = _make_event(
                target=f"file_{i}.py",
                ts=now + timedelta(seconds=i),
            )
            detector.add_event(event)
        assert len(detector.window) == 50  # Bounded by maxlen

    def test_cross_agent_no_false_positive(self):
        """Sequence patterns require same agent - different agents don't match."""
        detector = SequenceDetector()
        now = datetime.now(timezone.utc)

        # Agent A reads sensitive file
        event1 = _make_event(
            agent_id="agent-a",
            target=".env",
            action_type=ActionType.FILE_READ,
            ts=now,
        )
        detector.add_event(event1)

        # Agent B does web fetch (should NOT trigger read_then_exfil)
        event2 = _make_event(
            agent_id="agent-b",
            target="https://evil.com/upload",
            action_type=ActionType.WEB_FETCH,
            ts=now + timedelta(seconds=5),
            args={"domain": "evil.com"},
        )
        matches = detector.add_event(event2)
        assert not any(m.pattern_name == "read_then_exfil" for m in matches)
