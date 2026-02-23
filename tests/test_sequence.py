"""Tests for sequence pattern detection."""

from datetime import datetime, timedelta, timezone

from watchclaw.models import ActionEvent, ActionType
from watchclaw.sequence import SequenceDetector


def _make_event(
    action_type: ActionType,
    target: str,
    ts: datetime | None = None,
    args: dict | None = None,
) -> ActionEvent:
    return ActionEvent(
        ts=ts or datetime.now(timezone.utc),
        session_id="test",
        agent_id="test-agent",
        action_type=action_type,
        target=target,
        args=args or {},
        source="test",
    )


class TestSequenceDetector:
    def test_read_then_exfil_detected(self):
        """Reading a sensitive file then exfiltrating should be detected."""
        detector = SequenceDetector()
        now = datetime.now(timezone.utc)

        # Step 1: Read sensitive file
        matches = detector.add_event(_make_event(
            action_type=ActionType.FILE_READ,
            target="/project/.env",
            ts=now,
        ))
        assert not matches  # First event alone shouldn't match

        # Step 2: External web fetch within 120s
        matches = detector.add_event(_make_event(
            action_type=ActionType.WEB_FETCH,
            target="https://evil.com/upload",
            ts=now + timedelta(seconds=30),
        ))
        assert any(m.pattern_name == "read_then_exfil" for m in matches)

    def test_read_then_exfil_not_triggered_for_normal_file(self):
        """Reading a non-sensitive file should not trigger."""
        detector = SequenceDetector()
        now = datetime.now(timezone.utc)

        detector.add_event(_make_event(
            action_type=ActionType.FILE_READ,
            target="README.md",
            ts=now,
        ))
        matches = detector.add_event(_make_event(
            action_type=ActionType.WEB_FETCH,
            target="https://api.github.com/repos",
            ts=now + timedelta(seconds=30),
        ))
        assert not any(m.pattern_name == "read_then_exfil" for m in matches)

    def test_read_then_exfil_timeout(self):
        """Events more than 120s apart should not match."""
        detector = SequenceDetector()
        now = datetime.now(timezone.utc)

        detector.add_event(_make_event(
            action_type=ActionType.FILE_READ,
            target="/project/.env",
            ts=now,
        ))
        matches = detector.add_event(_make_event(
            action_type=ActionType.WEB_FETCH,
            target="https://evil.com/upload",
            ts=now + timedelta(seconds=200),
        ))
        assert not any(m.pattern_name == "read_then_exfil" for m in matches)

    def test_external_trigger_chain(self):
        """Web fetch followed by cognitive file write should be detected."""
        detector = SequenceDetector()
        now = datetime.now(timezone.utc)

        detector.add_event(_make_event(
            action_type=ActionType.WEB_FETCH,
            target="https://attacker.com/instructions",
            ts=now,
        ))
        matches = detector.add_event(_make_event(
            action_type=ActionType.FILE_WRITE,
            target="/workspace/SOUL.md",
            ts=now + timedelta(seconds=10),
        ))
        assert any(m.pattern_name == "external_trigger_chain" for m in matches)

    def test_config_then_escalate(self):
        """Config write followed by privileged exec should be detected."""
        detector = SequenceDetector()
        now = datetime.now(timezone.utc)

        detector.add_event(_make_event(
            action_type=ActionType.FILE_WRITE,
            target="/etc/app/config.yaml",
            ts=now,
        ))
        matches = detector.add_event(_make_event(
            action_type=ActionType.EXEC,
            target="sudo systemctl restart app",
            ts=now + timedelta(seconds=20),
        ))
        assert any(m.pattern_name == "config_then_escalate" for m in matches)

    def test_no_false_positive_normal_workflow(self):
        """Normal coding workflow should not trigger patterns."""
        detector = SequenceDetector()
        now = datetime.now(timezone.utc)

        events = [
            _make_event(ActionType.FILE_READ, "src/main.py", now),
            _make_event(ActionType.FILE_WRITE, "src/main.py", now + timedelta(seconds=5)),
            _make_event(ActionType.EXEC, "python -m pytest", now + timedelta(seconds=10)),
            _make_event(ActionType.FILE_READ, "src/utils.py", now + timedelta(seconds=15)),
        ]

        all_matches = []
        for event in events:
            all_matches.extend(detector.add_event(event))

        assert not all_matches
