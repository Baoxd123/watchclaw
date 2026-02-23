"""Core data models for WatchClaw."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ActionType(str, Enum):
    EXEC = "exec"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    WEB_FETCH = "web_fetch"
    MESSAGE_SEND = "message_send"
    TOOL_CALL = "tool_call"


class TaintLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    NORMAL = "NORMAL"
    NOTICE = "NOTICE"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


@dataclass
class ActionEvent:
    ts: datetime
    session_id: str
    agent_id: str
    action_type: ActionType
    target: str
    args: dict[str, Any] = field(default_factory=dict)
    result_summary: str = ""
    bytes_count: int = 0
    taint_level: TaintLevel = TaintLevel.NONE
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts.isoformat(),
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "action_type": self.action_type.value,
            "target": self.target,
            "args": self.args,
            "result_summary": self.result_summary,
            "bytes_count": self.bytes_count,
            "taint_level": self.taint_level.value,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActionEvent:
        return cls(
            ts=datetime.fromisoformat(data["ts"]),
            session_id=data["session_id"],
            agent_id=data["agent_id"],
            action_type=ActionType(data["action_type"]),
            target=data["target"],
            args=data.get("args", {}),
            result_summary=data.get("result_summary", ""),
            bytes_count=data.get("bytes_count", 0),
            taint_level=TaintLevel(data.get("taint_level", "none")),
            source=data.get("source", ""),
        )


@dataclass
class RunningStats:
    """Online statistics using Welford's algorithm."""
    count: int = 0
    mean: float = 0.0
    variance: float = 0.0
    min: float = float("inf")
    max: float = float("-inf")
    _m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self._m2 += delta * delta2
        self.variance = self._m2 / self.count if self.count > 0 else 0.0
        if value < self.min:
            self.min = value
        if value > self.max:
            self.max = value

    def z_score(self, value: float) -> float:
        if self.count < 2 or self.variance <= 0:
            return 0.0
        std = math.sqrt(self.variance)
        return (value - self.mean) / std

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "mean": self.mean,
            "variance": self.variance,
            "min": self.min,
            "max": self.max,
        }


@dataclass
class AgentProfile:
    agent_id: str
    hourly_activity: dict[int, float] = field(default_factory=lambda: {h: 0.0 for h in range(24)})
    signal_weights: dict[str, float] = field(default_factory=lambda: {
        "time_anomaly": 0.20,
        "user_idle": 0.20,
        "rate_burst": 0.15,
        "resource_anomaly": 0.15,
        "destination_anomaly": 0.15,
        "taint_flow": 0.15,
    })
    common_files: Counter = field(default_factory=Counter)
    common_domains: Counter = field(default_factory=Counter)
    common_commands: Counter = field(default_factory=Counter)
    tool_call_rate: RunningStats = field(default_factory=RunningStats)
    maturity: float = 0.0
    observations: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def record_observation(self) -> None:
        self.observations += 1
        self.maturity = min(1.0, self.observations / 100.0)

    def update_profile(self, event: ActionEvent) -> None:
        """Update profile from an observed event: maturity, time distribution,
        resource footprint (files, domains, commands)."""
        self.record_observation()
        self.tool_call_rate.update(1.0)

        # Increment raw hourly count
        hour = event.ts.hour
        self.hourly_activity[hour] = self.hourly_activity.get(hour, 0.0) + 1.0

        # Update resource footprint
        if event.action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE):
            if event.target:
                self.common_files[event.target] += 1

        if event.action_type == ActionType.EXEC:
            cmd = event.target or event.args.get("command", "")
            if cmd:
                self.common_commands[cmd] += 1

        domain = event.args.get("domain", "")
        if domain:
            self.common_domains[domain] += 1

    def get_hour_probability(self, hour: int) -> float:
        """Return learned probability for a given hour, dampened by maturity.

        Raw probability = count_at_hour / total_counts.
        Dampened by maturity so immature profiles don't over-trust sparse data.
        """
        total = sum(self.hourly_activity.values())
        if total <= 0:
            return 0.0
        raw_prob = self.hourly_activity.get(hour, 0.0) / total
        return raw_prob * self.maturity

    def on_user_feedback(
        self,
        alert_id: str,
        is_false_positive: bool,
        triggered_signals: list[str],
    ) -> None:
        """Adjust per-agent signal_weights based on user feedback.

        false positive  → lower triggered signal weights (×0.9)
        confirmed threat → raise triggered signal weights (×1.1)
        Weights are clamped to [0.1, 2.0].
        """
        factor = 0.9 if is_false_positive else 1.1
        for sig in triggered_signals:
            if sig in self.signal_weights:
                w = self.signal_weights[sig] * factor
                self.signal_weights[sig] = max(0.1, min(2.0, w))

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "hourly_activity": self.hourly_activity,
            "signal_weights": self.signal_weights,
            "common_files": dict(self.common_files),
            "common_domains": dict(self.common_domains),
            "common_commands": dict(self.common_commands),
            "tool_call_rate": self.tool_call_rate.to_dict(),
            "maturity": self.maturity,
            "observations": self.observations,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class Signal:
    name: str
    value: float
    weight: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "weight": self.weight,
            "reason": self.reason,
        }


@dataclass
class AnomalyResult:
    score: float
    signals: list[Signal]
    decision: Decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "signals": [s.to_dict() for s in self.signals],
            "decision": self.decision.value,
        }


@dataclass
class TaintEntry:
    source: str
    level: TaintLevel
    timestamp: datetime
    sensitivity: float = 0.5
    sanitized: bool = False
    sanitized_by: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "level": self.level.value,
            "timestamp": self.timestamp.isoformat(),
            "sensitivity": self.sensitivity,
            "sanitized": self.sanitized,
            "sanitized_by": self.sanitized_by,
        }


@dataclass
class AuditVerdict:
    verdict: Verdict
    confidence: float
    reason: str
    latency_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reason": self.reason,
        }
        if self.latency_ms is not None:
            d["latency_ms"] = self.latency_ms
        return d
