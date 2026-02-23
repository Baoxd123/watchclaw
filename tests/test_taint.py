"""Tests for taint tracking with exponential decay."""

from datetime import datetime, timedelta, timezone

from watchclaw.models import ActionEvent, ActionType, TaintEntry, TaintLevel
from watchclaw.taint import TaintTable, compute_file_sensitivity


class TestFileSensitivity:
    def test_env_file_high(self):
        assert compute_file_sensitivity(".env") >= 0.9

    def test_key_file_high(self):
        assert compute_file_sensitivity("server.key") >= 0.9

    def test_pem_file_high(self):
        assert compute_file_sensitivity("cert.pem") >= 0.9

    def test_markdown_low(self):
        assert compute_file_sensitivity("README.md") <= 0.2

    def test_python_low(self):
        assert compute_file_sensitivity("main.py") <= 0.4

    def test_credentials_json_high(self):
        assert compute_file_sensitivity("credentials.json") >= 0.9


class TestTaintDecay:
    def test_decay_halves_at_half_life(self):
        """Score should approximately halve after half_life seconds."""
        table = TaintTable(half_life=300.0)
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        entry = TaintEntry(
            source=".env",
            level=TaintLevel.HIGH,
            timestamp=t0,
            sensitivity=0.9,
        )

        score_at_0 = table.current_score(entry, now=t0)
        score_at_half = table.current_score(entry, now=t0 + timedelta(seconds=300))

        # Should be approximately half
        ratio = score_at_half / score_at_0 if score_at_0 > 0 else 0
        assert 0.45 <= ratio <= 0.55, f"Expected ~0.5 ratio, got {ratio}"

    def test_decay_approaches_zero(self):
        """Score should approach zero after many half-lives."""
        table = TaintTable(half_life=300.0)
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        entry = TaintEntry(
            source=".env",
            level=TaintLevel.HIGH,
            timestamp=t0,
            sensitivity=0.9,
        )

        score = table.current_score(entry, now=t0 + timedelta(seconds=3000))
        assert score < 0.01

    def test_sanitization_clears_taint(self):
        """Sanitized entries should return score of 0."""
        table = TaintTable(half_life=300.0)
        t0 = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        entry = TaintEntry(
            source=".env",
            level=TaintLevel.HIGH,
            timestamp=t0,
            sensitivity=0.9,
            sanitized=True,
            sanitized_by="user",
        )

        score = table.current_score(entry, now=t0)
        assert score == 0.0


class TestTaintTable:
    def test_on_action_creates_entry(self):
        table = TaintTable()
        event = ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="s",
            agent_id="a",
            action_type=ActionType.FILE_READ,
            target="/project/.env",
            source="test",
        )
        table.on_action(event)
        assert table.aggregate_taint() > 0

    def test_on_user_message_sanitizes(self):
        table = TaintTable()
        event = ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="s",
            agent_id="a",
            action_type=ActionType.FILE_READ,
            target="/project/.env",
            source="test",
        )
        table.on_action(event)
        assert table.aggregate_taint() > 0

        table.on_user_message("/project/.env")
        assert table.aggregate_taint() == 0.0

    def test_aggregate_empty_is_zero(self):
        table = TaintTable()
        assert table.aggregate_taint() == 0.0

    def test_low_sensitivity_no_entry(self):
        """Files with sensitivity < 0.5 should not create taint entries."""
        table = TaintTable()
        event = ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="s",
            agent_id="a",
            action_type=ActionType.FILE_READ,
            target="README.md",
            source="test",
        )
        table.on_action(event)
        assert table.aggregate_taint() == 0.0
