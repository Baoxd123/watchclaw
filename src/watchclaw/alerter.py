"""Discord webhook alerts with rich embed formatting."""

from __future__ import annotations

import json
import logging
import urllib.request
from datetime import datetime, timezone
from typing import Any

import watchclaw
from watchclaw.models import ActionEvent, AnomalyResult, AuditVerdict, Decision

logger = logging.getLogger(__name__)

# Embed colors
COLOR_ALERT = 0xFFAA00    # Orange for ALERT
COLOR_CRITICAL = 0xFF0000  # Red for CRITICAL
COLOR_NOTICE = 0x808080    # Gray


def _decision_color(decision: Decision) -> int:
    if decision == Decision.CRITICAL:
        return COLOR_CRITICAL
    elif decision == Decision.ALERT:
        return COLOR_ALERT
    return COLOR_NOTICE


class DiscordAlerter:
    """Sends security alerts via Discord webhook with rich embeds."""

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url

    def send(
        self,
        event: ActionEvent,
        anomaly: AnomalyResult,
        verdict: AuditVerdict | None = None,
    ) -> bool:
        """Send an alert to Discord. Returns True on success."""
        if not self.webhook_url:
            logger.warning("No Discord webhook URL configured, skipping alert")
            return False

        embed = self._build_embed(event, anomaly, verdict)
        payload = json.dumps({"embeds": [embed]}).encode("utf-8")

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.info("Alert sent to Discord: %d", resp.status)
                return resp.status in (200, 204)
        except Exception:
            logger.exception("Failed to send Discord alert")
            return False

    def _build_embed(
        self,
        event: ActionEvent,
        anomaly: AnomalyResult,
        verdict: AuditVerdict | None = None,
    ) -> dict[str, Any]:
        """Build a Discord embed payload."""
        # Top 3 signals by weighted value
        top_signals = sorted(
            anomaly.signals,
            key=lambda s: s.value * s.weight,
            reverse=True,
        )[:3]

        signal_lines = "\n".join(
            f"**{s.name}**: {s.value:.2f} (w={s.weight:.1f}) — {s.reason}"
            for s in top_signals
        )

        fields: list[dict[str, Any]] = [
            {"name": "Agent ID", "value": event.agent_id, "inline": True},
            {"name": "Action Type", "value": event.action_type.value, "inline": True},
            {"name": "Anomaly Score", "value": f"{anomaly.score:.2f}", "inline": True},
            {"name": "Target", "value": event.target[:200] or "N/A", "inline": False},
            {"name": "Top 3 Signals", "value": signal_lines[:1000] or "None", "inline": False},
        ]

        if verdict:
            fields.append({
                "name": "Auditor Verdict",
                "value": (
                    f"**{verdict.verdict.value}** "
                    f"(confidence: {verdict.confidence:.0%})\n"
                    f"{verdict.reason}"
                )[:500],
                "inline": False,
            })

        # NOTE: Discord components v2 needed for interactive reaction buttons
        # (approve/reject feedback). For now, users can react with emoji manually.

        embed: dict[str, Any] = {
            "title": f"WatchClaw {anomaly.decision.value}: {event.action_type.value}",
            "color": _decision_color(anomaly.decision),
            "fields": fields,
            "footer": {
                "text": f"{event.ts.isoformat()} | WatchClaw v{watchclaw.__version__}",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return embed
