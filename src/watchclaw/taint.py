"""Taint tracking with exponential decay."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path

from watchclaw.models import ActionEvent, ActionType, TaintEntry, TaintLevel

# Sensitivity scores by file extension
_SENSITIVITY_MAP: dict[str, float] = {
    ".env": 0.9,
    ".key": 0.95,
    ".pem": 0.95,
    ".p12": 0.95,
    ".pfx": 0.95,
    ".crt": 0.7,
    ".cer": 0.7,
    ".credentials": 0.9,
    ".secret": 0.9,
    ".token": 0.9,
    ".md": 0.1,
    ".txt": 0.2,
    ".log": 0.3,
    ".json": 0.4,
    ".yaml": 0.4,
    ".yml": 0.4,
    ".py": 0.3,
    ".js": 0.3,
    ".ts": 0.3,
}

# Sensitive filename patterns
_SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
    "authorized_keys",
    "secrets.yaml",
    "secrets.yml",
    "secrets.json",
    "secrets.key",
}


def compute_file_sensitivity(file_path: str) -> float:
    """Compute sensitivity score for a file based on extension and name."""
    p = Path(file_path)
    name = p.name.lower()

    if name in _SENSITIVE_NAMES:
        return 0.95

    for ext, score in _SENSITIVITY_MAP.items():
        if name.endswith(ext):
            return score

    suffix = p.suffix.lower()
    return _SENSITIVITY_MAP.get(suffix, 0.2)


def _level_to_score(level: TaintLevel) -> float:
    return {
        TaintLevel.NONE: 0.0,
        TaintLevel.LOW: 0.25,
        TaintLevel.MEDIUM: 0.5,
        TaintLevel.HIGH: 0.75,
        TaintLevel.CRITICAL: 1.0,
    }[level]


class TaintTable:
    """Tracks taint propagation with exponential decay."""

    def __init__(self, half_life: float = 300.0) -> None:
        self.half_life = half_life
        self._entries: dict[str, TaintEntry] = {}

    def current_score(self, entry: TaintEntry, now: datetime | None = None) -> float:
        """Compute current taint score with exponential decay.

        Formula per proposal 3.4: sensitivity * decay (no level multiplier).
        """
        if entry.sanitized:
            return 0.0
        if now is None:
            now = datetime.now(timezone.utc)
        elapsed = (now - entry.timestamp).total_seconds()
        decay = math.exp(-0.693 * elapsed / self.half_life)  # ln(2) ≈ 0.693
        return entry.sensitivity * decay

    def on_action(self, event: ActionEvent) -> None:
        """Record taint from an action event."""
        if event.action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE):
            sensitivity = compute_file_sensitivity(event.target)
            if sensitivity >= 0.5:
                level = TaintLevel.HIGH if sensitivity >= 0.9 else TaintLevel.MEDIUM
                self._entries[event.target] = TaintEntry(
                    source=event.target,
                    level=level,
                    timestamp=event.ts,
                    sensitivity=sensitivity,
                )
        elif event.action_type == ActionType.WEB_FETCH:
            self._entries[f"web:{event.target}"] = TaintEntry(
                source=event.target,
                level=TaintLevel.MEDIUM,
                timestamp=event.ts,
                sensitivity=0.5,
            )
        elif event.action_type == ActionType.EXEC:
            self._entries[f"exec:{event.target}"] = TaintEntry(
                source=event.target,
                level=TaintLevel.LOW,
                timestamp=event.ts,
                sensitivity=0.3,
            )

    # Transfer keywords that indicate user approval (proposal 3.4)
    _SANITIZE_KEYWORDS = {
        "send", "sent", "upload", "transfer", "share", "post",
        "发送", "上传", "传输", "分享",
        "approve", "approved", "confirm", "confirmed", "ok", "yes", "allow",
    }

    def on_user_message(self, target: str = "", user: str = "user", message: str = "") -> None:
        """Sanitize taint when user explicitly approves.

        If a specific target is given, sanitize that entry.
        If a message is given, scan for transfer keywords and auto-sanitize
        all active entries (proposal 3.4: user approval clears taint).
        """
        if target and target in self._entries:
            self._entries[target].sanitized = True
            self._entries[target].sanitized_by = user

        if message:
            words = set(message.lower().split())
            if words & self._SANITIZE_KEYWORDS:
                for entry in self._entries.values():
                    if not entry.sanitized:
                        entry.sanitized = True
                        entry.sanitized_by = user

    def aggregate_taint(self, now: datetime | None = None) -> float:
        """Get the max taint score across all active entries."""
        if not self._entries:
            return 0.0
        return max(
            (self.current_score(e, now) for e in self._entries.values()),
            default=0.0,
        )

    def get_entries(self) -> list[TaintEntry]:
        return list(self._entries.values())
