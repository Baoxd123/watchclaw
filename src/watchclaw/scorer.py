"""Layer 2: Anomaly scoring with 6 signals."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from watchclaw.models import (
    ActionEvent,
    ActionType,
    AgentProfile,
    AnomalyResult,
    Decision,
    Signal,
)
from watchclaw.parser import _extract_file_from_exec, _extract_url_from_exec
from watchclaw.taint import TaintTable, compute_file_sensitivity

logger = logging.getLogger(__name__)

# Decision thresholds
THRESHOLD_NORMAL = 0.3
THRESHOLD_NOTICE = 0.5
THRESHOLD_ALERT = 0.7

# High-confidence malicious domains — score 1.0
KNOWN_BAD_DOMAINS: set[str] = {
    "evil-exfil.com",
    "requestbin.net", "hookbin.com", "burpcollaborator.net",
}

# Suspicious but legitimate-use-possible domains — score 0.6
# These are commonly used in attacks but also have benign uses.
# They contribute destination_anomaly only when combined with other signals.
SUSPICIOUS_DOMAINS: set[str] = {
    "pastebin.com", "transfer.sh", "ngrok.io", "ngrok-free.app",
    "webhook.site", "pipedream.net", "beeceptor.com",
}

# Suspicious TLDs commonly used by newly-registered throwaway domains
_SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs (abuse-heavy)
    ".xyz", ".top", ".work", ".click", ".link", ".buzz", ".surf",
    ".icu", ".monster", ".rest", ".sbs",
}


def _is_newly_registered_heuristic(domain: str) -> bool:
    """Heuristic: flag domains on suspicious TLDs as potentially newly-registered.

    Without live WHOIS/DNS-age data, suspicious TLD is the best proxy.
    """
    domain_lower = domain.lower()
    return any(domain_lower.endswith(tld) for tld in _SUSPICIOUS_TLDS)

# Default conservative weights for cold-start blending
DEFAULT_WEIGHTS: dict[str, float] = {
    "time_anomaly": 0.20,
    "user_idle": 0.20,
    "rate_burst": 0.15,
    "resource_anomaly": 0.15,
    "destination_anomaly": 0.15,
    "taint_flow": 0.15,
}


def get_effective_weight(profile: AgentProfile, signal_name: str) -> float:
    """Blend default conservative weight with personal weight based on maturity.

    New agents (maturity=0) get 100% default weights.
    Mature agents (maturity=1) get 100% personal weights.
    """
    default_w = DEFAULT_WEIGHTS.get(signal_name, 1.0)
    personal_w = profile.signal_weights.get(signal_name, 1.0)
    if profile.maturity >= 1.0:
        return personal_w
    return default_w * (1.0 - profile.maturity) + personal_w * profile.maturity


def _decide(score: float) -> Decision:
    if score < THRESHOLD_NORMAL:
        return Decision.NORMAL
    elif score < THRESHOLD_NOTICE:
        return Decision.NOTICE
    elif score < THRESHOLD_ALERT:
        return Decision.ALERT
    else:
        return Decision.CRITICAL


class AnomalyScorer:
    """Computes anomaly score from 6 signals weighted by agent profile."""

    def __init__(self, taint_table: TaintTable | None = None) -> None:
        self.taint_table = taint_table or TaintTable()
        self._last_user_message: datetime | None = None

    def on_user_message(self, ts: datetime | None = None) -> None:
        self._last_user_message = ts or datetime.now(timezone.utc)

    def score(
        self,
        event: ActionEvent,
        profile: AgentProfile,
        now: datetime | None = None,
    ) -> AnomalyResult:
        """Score an action event using 6 signals."""
        if now is None:
            now = datetime.now(timezone.utc)

        signals: list[Signal] = []

        # 1. Time anomaly: 1.0 - learned hour probability (dampened by maturity)
        # Cold-start dampening: for immature profiles, "no data" should mean
        # "unknown" (low signal) not "highly anomalous" (high signal).
        # Ramps from 0.3 at maturity=0 to 1.0 at maturity>=0.2.
        hour = now.hour
        activity = profile.get_hour_probability(hour)
        cold_start_factor = min(1.0, 0.3 + 3.5 * profile.maturity)
        time_val = (1.0 - activity) * cold_start_factor
        signals.append(Signal(
            name="time_anomaly",
            value=time_val,
            weight=get_effective_weight(profile, "time_anomaly"),
            reason=f"Hour {hour} activity level: {activity:.2f} (cold_start={cold_start_factor:.2f})",
        ))

        # 2. User idle: based on time since last user message
        if self._last_user_message:
            idle_seconds = (now - self._last_user_message).total_seconds()
            idle_val = min(1.0, idle_seconds / 14400.0)  # 4h → 1.0
        else:
            # No message recorded yet → moderate-low default (we don't know, so
            # don't assume highly idle)
            idle_val = 0.2
        signals.append(Signal(
            name="user_idle",
            value=idle_val,
            weight=get_effective_weight(profile, "user_idle"),
            reason=f"User idle score: {idle_val:.2f}",
        ))

        # 3. Rate burst: z-score of current action rate (only scores when z > 2)
        rate_z = profile.tool_call_rate.z_score(1.0)
        rate_val = min(1.0, max(0.0, (rate_z - 2.0) / 3.0))
        signals.append(Signal(
            name="rate_burst",
            value=rate_val,
            weight=get_effective_weight(profile, "rate_burst"),
            reason=f"Rate z-score: {rate_z:.2f}",
        ))

        # 4. Resource anomaly: additive scoring per proposal 3.2.2
        #    +0.4 for unknown file (not in common_files)
        #    +0.6 for sensitive file (sensitivity >= 0.5)
        sensitivity = compute_file_sensitivity(event.target)
        known = event.target in profile.common_files
        resource_val = 0.0
        if event.action_type in (ActionType.FILE_READ, ActionType.FILE_WRITE):
            if not known:
                resource_val += 0.4
            if sensitivity >= 0.5:
                resource_val += 0.6
        elif event.action_type == ActionType.EXEC:
            # Analyze exec command string for sensitive file paths and URLs
            exec_file = _extract_file_from_exec(event.target)
            if exec_file:
                exec_sensitivity = compute_file_sensitivity(exec_file)
                if exec_sensitivity >= 0.5:
                    resource_val += 0.6
                if exec_file not in profile.common_files:
                    resource_val += 0.4
            exec_url = _extract_url_from_exec(event.target)
            if exec_url:
                resource_val += 0.3
        resource_val = min(1.0, resource_val)
        signals.append(Signal(
            name="resource_anomaly",
            value=resource_val,
            weight=get_effective_weight(profile, "resource_anomaly"),
            reason=f"Target sensitivity: {sensitivity:.2f}, known: {known}",
        ))

        # 5. Destination anomaly: additive 3-tier threat intel (proposal 3.2.2)
        #    known_bad → 1.0
        #    additive: unknown(+0.4) + newly_registered(+0.5), capped at 1.0
        #    known → 0.1
        domain = event.args.get("domain", "")
        if domain:
            if domain in KNOWN_BAD_DOMAINS:
                dest_val = 1.0
                dest_reason = f"Domain: {domain}, known_bad"
            elif domain in SUSPICIOUS_DOMAINS:
                dest_val = 0.6
                dest_reason = f"Domain: {domain}, suspicious (dual-use)"
            elif domain in profile.common_domains:
                dest_val = 0.1
                dest_reason = f"Domain: {domain}, known"
            else:
                dest_val = 0.4  # unknown
                dest_reason = f"Domain: {domain}, unknown"
                if _is_newly_registered_heuristic(domain):
                    dest_val += 0.5  # newly registered
                    dest_reason = f"Domain: {domain}, unknown+newly_registered"
                dest_val = min(1.0, dest_val)
        else:
            dest_val = 0.0
            dest_reason = "Domain: N/A"
        signals.append(Signal(
            name="destination_anomaly",
            value=dest_val,
            weight=get_effective_weight(profile, "destination_anomaly"),
            reason=dest_reason,
        ))

        # 6. Taint flow: only relevant for outgoing actions (data exfiltration risk)
        raw_taint = self.taint_table.aggregate_taint(now)
        is_outgoing = event.action_type in (
            ActionType.WEB_FETCH, ActionType.EXEC, ActionType.MESSAGE_SEND,
        )
        if is_outgoing and raw_taint > 0.1:
            taint_val = raw_taint
        else:
            taint_val = 0.0
        signals.append(Signal(
            name="taint_flow",
            value=taint_val,
            weight=get_effective_weight(profile, "taint_flow"),
            reason=f"Aggregate taint: {raw_taint:.3f}, outgoing: {is_outgoing}",
        ))

        # Compute weighted sum with normalization
        total_weight = sum(s.weight for s in signals)
        if total_weight > 0:
            score = sum(s.value * s.weight for s in signals) / total_weight
        else:
            score = 0.0

        score = min(1.0, max(0.0, score))
        decision = _decide(score)

        return AnomalyResult(score=score, signals=signals, decision=decision)
