"""Tests for CLI commands."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from watchclaw.cli import main
from watchclaw.models import ActionType, TaintLevel


def _write_action_log(tmp_dir: Path, entries: list[dict]) -> Path:
    log_path = tmp_dir / "action.log"
    with log_path.open("w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return log_path


def _make_log_entry(
    agent_id: str = "test-agent",
    action_type: str = "file_read",
    target: str = "/tmp/test.txt",
    decision: str = "NORMAL",
    score: float = 0.1,
) -> dict:
    return {
        "event": {
            "ts": "2025-01-15T10:30:00+00:00",
            "session_id": "sess-1",
            "agent_id": agent_id,
            "action_type": action_type,
            "target": target,
            "args": {},
            "result_summary": "",
            "bytes_count": 0,
            "taint_level": "none",
            "source": "",
        },
        "anomaly": {
            "score": score,
            "signals": [],
            "decision": decision,
        },
        "rules": [],
        "sequences": [],
    }


class TestProfileCommand:
    def test_profile_shows_agent_stats(self, tmp_path):
        entries = [
            _make_log_entry("agent-a", decision="NORMAL"),
            _make_log_entry("agent-a", decision="ALERT"),
            _make_log_entry("agent-a", decision="CRITICAL"),
            _make_log_entry("agent-b", decision="NORMAL"),
        ]
        log_path = _write_action_log(tmp_path, entries)

        from watchclaw.cli import cmd_profile
        import argparse

        # Create a mock Path that returns our tmp log for the known path
        real_log = log_path

        class FakePath:
            """Minimal Path stand-in that redirects the action log path."""
            def __init__(self, p):
                if str(p) == "/tmp/watchclaw/action.log":
                    self._p = real_log
                else:
                    self._p = Path(p)

            def exists(self):
                return self._p.exists()

            def open(self, *a, **kw):
                return self._p.open(*a, **kw)

            def read_text(self, *a, **kw):
                return self._p.read_text(*a, **kw)

        out = StringIO()
        with patch("watchclaw.cli.Path", FakePath), patch("sys.stdout", out):
            ns = argparse.Namespace(agent_id="agent-a")
            cmd_profile(ns)

        output = out.getvalue()
        assert "agent-a" in output
        assert "3" in output  # 3 events
        assert "1" in output  # 1 alert

    def test_profile_no_log(self):
        from watchclaw.cli import cmd_profile
        import argparse

        class FakePath:
            def __init__(self, p):
                pass
            def exists(self):
                return False

        out = StringIO()
        ns = argparse.Namespace(agent_id=None)
        with patch("watchclaw.cli.Path", FakePath), patch("sys.stdout", out):
            cmd_profile(ns)

        assert "No action log" in out.getvalue()


class TestRulesCommand:
    def test_rules_list(self):
        """Verify watchclaw rules lists all loaded rules."""
        out = StringIO()
        with patch("sys.stdout", out):
            main(["rules"])

        output = out.getvalue()
        assert "WC-HARD-001" in output
        assert "WC-HARD-002" in output
        assert "WC-HARD-003" in output
        assert "WC-HARD-004" in output
        assert "WC-HARD-005" in output
        assert "critical" in output
        assert "block" in output

    def test_rules_test_matching_event(self, tmp_path):
        """Verify --test correctly matches an event against rules."""
        event_data = {
            "ts": "2025-01-15T10:30:00+00:00",
            "session_id": "sess-1",
            "agent_id": "test-agent",
            "action_type": "file_write",
            "target": "/home/user/watchclaw/config.py",
            "args": {},
            "result_summary": "",
            "bytes_count": 0,
            "taint_level": "none",
            "source": "",
        }
        event_file = tmp_path / "event.json"
        event_file.write_text(json.dumps(event_data))

        out = StringIO()
        with patch("sys.stdout", out):
            main(["rules", "--test", str(event_file)])

        output = out.getvalue()
        assert "WC-HARD-001" in output
        assert "MATCH" in output

    def test_rules_test_no_match(self, tmp_path):
        """Verify --test reports no match for benign events."""
        event_data = {
            "ts": "2025-01-15T10:30:00+00:00",
            "session_id": "sess-1",
            "agent_id": "test-agent",
            "action_type": "file_read",
            "target": "/tmp/readme.txt",
            "args": {},
            "result_summary": "",
            "bytes_count": 0,
            "taint_level": "none",
            "source": "",
        }
        event_file = tmp_path / "event.json"
        event_file.write_text(json.dumps(event_data))

        out = StringIO()
        with patch("sys.stdout", out):
            main(["rules", "--test", str(event_file)])

        assert "No rules matched" in out.getvalue()


class TestVersionCommand:
    def test_version(self):
        out = StringIO()
        with patch("sys.stdout", out):
            main(["version"])
        assert "watchclaw" in out.getvalue()
        assert "0.1.0" in out.getvalue()


class TestUserFeedback:
    """Tests for AgentProfile.on_user_feedback."""

    def test_false_positive_lowers_weights(self):
        from watchclaw.models import AgentProfile
        profile = AgentProfile(agent_id="test")
        original = profile.signal_weights["time_anomaly"]

        profile.on_user_feedback("alert-1", is_false_positive=True, triggered_signals=["time_anomaly"])

        assert profile.signal_weights["time_anomaly"] < original
        assert abs(profile.signal_weights["time_anomaly"] - original * 0.9) < 1e-9

    def test_confirmed_threat_raises_weights(self):
        from watchclaw.models import AgentProfile
        profile = AgentProfile(agent_id="test")
        original = profile.signal_weights["resource_anomaly"]

        profile.on_user_feedback("alert-2", is_false_positive=False, triggered_signals=["resource_anomaly"])

        assert profile.signal_weights["resource_anomaly"] > original
        assert abs(profile.signal_weights["resource_anomaly"] - original * 1.1) < 1e-9

    def test_weight_clamped_to_min(self):
        from watchclaw.models import AgentProfile
        profile = AgentProfile(agent_id="test")
        profile.signal_weights["taint_flow"] = 0.1

        profile.on_user_feedback("alert-3", is_false_positive=True, triggered_signals=["taint_flow"])

        assert profile.signal_weights["taint_flow"] == 0.1

    def test_weight_clamped_to_max(self):
        from watchclaw.models import AgentProfile
        profile = AgentProfile(agent_id="test")
        profile.signal_weights["taint_flow"] = 2.0

        profile.on_user_feedback("alert-4", is_false_positive=False, triggered_signals=["taint_flow"])

        assert profile.signal_weights["taint_flow"] == 2.0

    def test_multiple_signals(self):
        from watchclaw.models import AgentProfile
        profile = AgentProfile(agent_id="test")
        sigs = ["time_anomaly", "user_idle", "rate_burst"]
        originals = {s: profile.signal_weights[s] for s in sigs}

        profile.on_user_feedback("alert-5", is_false_positive=True, triggered_signals=sigs)

        for s in sigs:
            expected = originals[s] * 0.9
            assert abs(profile.signal_weights[s] - expected) < 1e-9

    def test_unknown_signal_ignored(self):
        from watchclaw.models import AgentProfile
        profile = AgentProfile(agent_id="test")
        original = dict(profile.signal_weights)

        profile.on_user_feedback("alert-6", is_false_positive=True, triggered_signals=["nonexistent_signal"])

        assert profile.signal_weights == original
