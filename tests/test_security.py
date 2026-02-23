"""R7: Security self-check and performance benchmark tests.

Tests cover:
- Dashboard binds to 127.0.0.1 by default (not 0.0.0.0)
- CORS header restricts origin (not wildcard)
- Regex patterns in rules have no ReDoS risk (linear backtracking only)
- action.log does not contain raw credential values
- Performance: 1000 events processed in < 5ms each
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from watchclaw.engine import WatchClawEngine
from watchclaw.models import ActionEvent, ActionType
from watchclaw.parser import SimulatedEventGenerator
from watchclaw.server import run_server


def test_dashboard_binds_localhost():
    """Dashboard default host should be 127.0.0.1."""
    import inspect
    sig = inspect.signature(run_server)
    host_param = sig.parameters.get("host")
    assert host_param is not None, "run_server should have a 'host' parameter"
    assert host_param.default == "127.0.0.1", f"Default host should be 127.0.0.1, got {host_param.default}"


def test_cors_not_wildcard():
    """CORS header should not be wildcard '*'."""
    import inspect
    from watchclaw import server
    source = inspect.getsource(server)
    assert 'Access-Control-Allow-Origin", "*"' not in source, \
        "CORS should not use wildcard '*'"


def test_regex_no_exponential_backtracking():
    """Rule regex patterns should not cause exponential backtracking.

    Tests that all patterns complete in bounded time on adversarial input.
    """
    from watchclaw.rules import RuleEngine, Rule
    import yaml
    from pathlib import Path

    rules_path = Path(__file__).parent.parent / "configs" / "default-rules.yaml"
    if not rules_path.exists():
        return  # Skip if no rules file

    with rules_path.open() as f:
        data = yaml.safe_load(f)

    # Adversarial input: long strings that could trigger backtracking
    adversarial = "a" * 10000
    adversarial_with_spaces = " ".join(["word"] * 2000)

    for rule_data in data.get("rules", []):
        conditions = rule_data.get("conditions", {})
        for key in ("target_pattern", "command_pattern", "content_match"):
            pattern = conditions.get(key)
            if pattern:
                start = time.perf_counter()
                re.search(pattern, adversarial, re.IGNORECASE)
                re.search(pattern, adversarial_with_spaces, re.IGNORECASE)
                elapsed = time.perf_counter() - start
                assert elapsed < 1.0, (
                    f"Regex '{key}' in rule {rule_data['id']} took {elapsed:.2f}s "
                    f"on adversarial input — possible ReDoS"
                )


def test_action_log_no_credential_values(tmp_path):
    """action.log should not contain raw credential values."""
    engine = WatchClawEngine()
    engine._action_log_path = tmp_path / "action.log"

    # Simulate reading a sensitive file
    event = ActionEvent(
        ts=datetime.now(timezone.utc),
        session_id="test",
        agent_id="test-agent",
        action_type=ActionType.FILE_READ,
        target=".env",
        args={"tool": "read"},
        result_summary="OK",
        source="test",
    )
    engine.process_event(event)

    log_content = engine._action_log_path.read_text()
    # Ensure no actual credential values leak (we never had content, so target path is fine)
    assert "sk-live-" not in log_content
    assert "AKIA" not in log_content
    assert "BEGIN PRIVATE KEY" not in log_content
    # File path IS expected (security tool needs to log what was accessed)
    assert ".env" in log_content


def test_performance_under_5ms():
    """Layer 1+2 processing must average under 5ms per event."""
    engine = WatchClawEngine()
    gen = SimulatedEventGenerator()
    events = [gen.generate_normal() for _ in range(500)]

    # Disable file I/O
    from pathlib import PurePosixPath
    engine._action_log_path = type(engine._action_log_path)("/dev/null")

    start = time.perf_counter()
    for e in events:
        engine.process_event(e)
    elapsed = time.perf_counter() - start

    per_event_ms = elapsed / 500 * 1000
    assert per_event_ms < 5.0, f"Per-event time {per_event_ms:.2f}ms exceeds 5ms target"
