"""Sequence pattern detection for multi-step attacks."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path

from watchclaw.models import ActionEvent, ActionType
from watchclaw.taint import compute_file_sensitivity


@dataclass
class SequenceMatch:
    pattern_name: str
    score_boost: float
    description: str


# Sensitive file patterns
_COGNITIVE_FILES = {"soul.md", "identity.md", "agents.md", "claude.md", "system.md", "memory.md"}


def _is_sensitive_file(target: str) -> bool:
    return compute_file_sensitivity(target) >= 0.7


def _is_cognitive_file(target: str) -> bool:
    return Path(target).name.lower() in _COGNITIVE_FILES


def _is_external_action(event: ActionEvent) -> bool:
    return event.action_type in (ActionType.WEB_FETCH, ActionType.MESSAGE_SEND) or (
        event.action_type == ActionType.EXEC
        and any(
            kw in event.target.lower()
            for kw in ("curl", "wget", "nc", "ssh", "scp", "rsync")
        )
    )


def _is_privileged_exec(event: ActionEvent) -> bool:
    return event.action_type == ActionType.EXEC and any(
        kw in event.target.lower()
        for kw in ("sudo", "chmod", "chown", "systemctl", "launchctl", "crontab")
    )


def _is_config_write(event: ActionEvent) -> bool:
    if event.action_type != ActionType.FILE_WRITE:
        return False
    name = Path(event.target).name.lower()
    return name.endswith((".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".conf"))


class SequenceDetector:
    """Detects multi-step attack patterns using a sliding window."""

    def __init__(self, window_size: int = 50) -> None:
        self.window: deque[ActionEvent] = deque(maxlen=window_size)

    def add_event(self, event: ActionEvent) -> list[SequenceMatch]:
        """Add an event and check for matching patterns."""
        self.window.append(event)
        matches: list[SequenceMatch] = []

        for checker in (
            self._check_read_then_exfil,
            self._check_config_then_escalate,
            self._check_external_trigger_chain,
        ):
            result = checker()
            if result:
                matches.append(result)

        return matches

    def _check_read_then_exfil(self) -> SequenceMatch | None:
        """Detect: file_read(sensitive) -> web_fetch/exec(external) within 120s.

        Only triggers when the latest event is the external action (second step).
        Both events must belong to the same agent.
        """
        events = list(self.window)
        if not events:
            return None
        current = events[-1]
        if not _is_external_action(current):
            return None
        for j in range(len(events) - 2, -1, -1):
            prior = events[j]
            if prior.agent_id != current.agent_id:
                continue
            elapsed = (current.ts - prior.ts).total_seconds()
            if elapsed > 120:
                break
            if prior.action_type == ActionType.FILE_READ and _is_sensitive_file(prior.target):
                return SequenceMatch(
                    pattern_name="read_then_exfil",
                    score_boost=0.4,
                    description=f"Sensitive file read ({prior.target}) followed by external action ({current.target})",
                )
        return None

    def _check_config_then_escalate(self) -> SequenceMatch | None:
        """Detect: file_write(config) -> exec(privileged) within 60s.

        Only triggers when the latest event is the privileged exec (second step).
        Both events must belong to the same agent.
        """
        events = list(self.window)
        if not events:
            return None
        current = events[-1]
        if not _is_privileged_exec(current):
            return None
        for j in range(len(events) - 2, -1, -1):
            prior = events[j]
            if prior.agent_id != current.agent_id:
                continue
            elapsed = (current.ts - prior.ts).total_seconds()
            if elapsed > 60:
                break
            if _is_config_write(prior):
                return SequenceMatch(
                    pattern_name="config_then_escalate",
                    score_boost=0.5,
                    description=f"Config write ({prior.target}) followed by privileged exec ({current.target})",
                )
        return None

    def _check_external_trigger_chain(self) -> SequenceMatch | None:
        """Detect: web_fetch -> file_write(cognitive) within 30s.

        Only triggers when the latest event is the cognitive file write (second step).
        Both events must belong to the same agent.
        """
        events = list(self.window)
        if not events:
            return None
        current = events[-1]
        if current.action_type != ActionType.FILE_WRITE or not _is_cognitive_file(current.target):
            return None
        for j in range(len(events) - 2, -1, -1):
            prior = events[j]
            if prior.agent_id != current.agent_id:
                continue
            elapsed = (current.ts - prior.ts).total_seconds()
            if elapsed > 30:
                break
            if prior.action_type == ActionType.WEB_FETCH:
                return SequenceMatch(
                    pattern_name="external_trigger_chain",
                    score_boost=0.6,
                    description=f"Web fetch ({prior.target}) followed by cognitive file write ({current.target})",
                )
        return None
