"""Layer 1: YAML rule engine for hard security rules."""

from __future__ import annotations

import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from watchclaw.models import ActionEvent

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: str
    action: str
    description: str


@dataclass
class SlidingWindow:
    """Deque-based sliding window for count_within tracking."""
    timestamps: deque[float] = field(default_factory=deque)
    max_count: int = 3
    window_seconds: float = 60.0

    def add_and_check(self, ts: float) -> bool:
        """Add a timestamp and return True if count exceeded within window."""
        self.timestamps.append(ts)
        cutoff = ts - self.window_seconds
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()
        return len(self.timestamps) >= self.max_count


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    action: str
    conditions: dict[str, Any]
    count_within: dict[str, int] | None = None

    @property
    def is_sequence_rule(self) -> bool:
        """Sequence rules are evaluated by the SequenceDetector, not here."""
        return "sequence" in self.conditions

    def matches(self, event: ActionEvent) -> bool:
        """Check if an event matches this rule's conditions.

        Sequence rules are skipped (they are evaluated by SequenceDetector).
        """
        # Sequence rules are multi-event; skip single-event matching
        if self.is_sequence_rule:
            return False

        if "action_type" in self.conditions:
            expected = self.conditions["action_type"]
            if isinstance(expected, list):
                if event.action_type.value not in expected:
                    return False
            elif event.action_type.value != expected:
                return False

        if "target_pattern" in self.conditions:
            pattern = self.conditions["target_pattern"]
            if not re.search(pattern, event.target, re.IGNORECASE):
                return False

        if "command_pattern" in self.conditions:
            pattern = self.conditions["command_pattern"]
            target_and_args = event.target + " " + str(event.args)
            if not re.search(pattern, target_and_args, re.IGNORECASE):
                return False

        if "content_match" in self.conditions:
            pattern = self.conditions["content_match"]
            content = event.args.get("content", "") + event.result_summary
            if not re.search(pattern, content, re.IGNORECASE):
                return False

        if "taint_source" in self.conditions:
            required = self.conditions["taint_source"].upper()
            # EXTERNAL means taint_level must be non-NONE (data came from outside)
            if required == "EXTERNAL":
                if event.taint_level.value == "none":
                    return False

        return True


class RuleEngine:
    """Evaluates ActionEvents against YAML-defined rules."""

    def __init__(self) -> None:
        self.rules: list[Rule] = []
        self._windows: dict[str, SlidingWindow] = {}

    def load_rules(self, path: str | Path) -> None:
        """Load rules from a YAML file."""
        path = Path(path)
        with path.open() as f:
            data = yaml.safe_load(f)

        rules_data = data.get("rules", [])
        for rd in rules_data:
            rule = Rule(
                id=rd["id"],
                name=rd["name"],
                description=rd.get("description", ""),
                severity=rd.get("severity", "medium"),
                action=rd.get("action", "alert"),
                conditions=rd.get("conditions", {}),
                count_within=rd.get("count_within"),
            )
            self.rules.append(rule)

        logger.info("Loaded %d rules from %s", len(self.rules), path)

    def evaluate(self, event: ActionEvent) -> list[RuleMatch]:
        """Evaluate an event against all rules. Returns list of matches."""
        matches: list[RuleMatch] = []

        for rule in self.rules:
            if not rule.matches(event):
                continue

            if rule.count_within:
                window_key = f"{rule.id}:{event.agent_id}"
                if window_key not in self._windows:
                    self._windows[window_key] = SlidingWindow(
                        max_count=rule.count_within["count"],
                        window_seconds=float(rule.count_within["seconds"]),
                    )
                window = self._windows[window_key]
                ts = event.ts.timestamp()
                if not window.add_and_check(ts):
                    continue

            matches.append(RuleMatch(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                action=rule.action,
                description=rule.description,
            ))

        return matches
