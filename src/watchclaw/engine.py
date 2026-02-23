"""Main WatchClaw engine: ties all layers together."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from watchclaw.alerter import DiscordAlerter
from watchclaw.auditor import LLMAuditor
from watchclaw.models import ActionEvent, ActionType, AgentProfile, AnomalyResult, AuditVerdict, Decision
from watchclaw.parser import FileSystemWatcher, OpenClawLogParser, SimulatedEventGenerator
from watchclaw.rules import RuleEngine
from watchclaw.scorer import AnomalyScorer, _decide
from watchclaw.sequence import SequenceDetector, SequenceMatch, _is_cognitive_file
from watchclaw.taint import TaintTable, compute_file_sensitivity

logger = logging.getLogger(__name__)


class WatchClawEngine:
    """Orchestrates all security monitoring layers."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

        self.taint_table = TaintTable(
            half_life=self.config.get("taint_half_life", 300.0),
        )
        self.rule_engine = RuleEngine()
        self.scorer = AnomalyScorer(taint_table=self.taint_table)
        self.sequence_detector = SequenceDetector()
        self.auditor = LLMAuditor()
        self.alerter = DiscordAlerter(
            webhook_url=self.config.get("discord_webhook_url"),
        )

        self._profiles: dict[str, AgentProfile] = {}
        self._action_log_path = Path(
            self.config.get("action_log", "/tmp/watchclaw/action.log")
        )
        self._log_dir = self._action_log_path.parent
        self._sequence_log_path = self._log_dir / "sequence.log"
        self._audit_log_path = self._log_dir / "audit.log"
        self._cognitive_log_path = self._log_dir / "cognitive.log"
        self._running = False
        # Last processing results (for CLI display)
        self._last_seq_matches: list[SequenceMatch] = []
        self._last_rule_matches: list = []

        # Load rules
        rules_path = self.config.get("rules_path")
        if rules_path and Path(rules_path).exists():
            self.rule_engine.load_rules(rules_path)

    def _get_profile(self, agent_id: str) -> AgentProfile:
        if agent_id not in self._profiles:
            self._profiles[agent_id] = AgentProfile(agent_id=agent_id)
        return self._profiles[agent_id]

    def process_event(self, event: ActionEvent) -> AnomalyResult:
        """Process a single action event through all layers.

        Catches exceptions to prevent a single bad event from crashing the engine.
        """
        try:
            return self._process_event_inner(event)
        except Exception:
            logger.exception("Error processing event for agent=%s target=%s", event.agent_id, event.target)
            # Return a safe default so the engine keeps running
            return AnomalyResult(score=0.0, signals=[], decision=Decision.NOTICE)

    def _process_event_inner(self, event: ActionEvent) -> AnomalyResult:
        """Inner processing logic (unwrapped)."""
        profile = self._get_profile(event.agent_id)

        # Layer 1: Hard rules
        rule_matches = self.rule_engine.evaluate(event)
        self._last_rule_matches = rule_matches
        for match in rule_matches:
            logger.warning(
                "Rule %s matched: %s (severity=%s)",
                match.rule_id, match.rule_name, match.severity,
            )

        # Check if Layer 1 blocks this event (critical/block → immediate CRITICAL)
        hard_rule_escalation = False
        for match in rule_matches:
            if match.action == "block" or match.severity == "critical":
                hard_rule_escalation = True
                break

        # Update taint tracking
        self.taint_table.on_action(event)

        # Check sequence patterns
        seq_matches = self.sequence_detector.add_event(event)
        self._last_seq_matches = seq_matches
        seq_boost = sum(m.score_boost for m in seq_matches)

        # Layer 2: Anomaly scoring — only for PASS events from Layer 1 (proposal 3.1)
        if hard_rule_escalation:
            # Hard-rule BLOCK: skip Layer 2, set CRITICAL directly
            anomaly = AnomalyResult(
                score=0.9, signals=[], decision=Decision.CRITICAL,
            )
        else:
            anomaly = self.scorer.score(event, profile)

            # Apply sequence boost
            if seq_boost > 0:
                anomaly.score = min(1.0, anomaly.score + seq_boost)
                anomaly.decision = _decide(anomaly.score)

            # Apply non-block rule matches (alerts)
            for match in rule_matches:
                if match.action == "alert" and anomaly.decision not in (
                    Decision.ALERT, Decision.CRITICAL,
                ):
                    anomaly.decision = Decision.ALERT
                    anomaly.score = max(anomaly.score, 0.5)

        # Layer 3: LLM audit (only if escalated by anomaly scoring, not hard rules)
        # Hard rule BLOCKs are immediate — no LLM audit needed (proposal 3.1)
        verdict = None
        if anomaly.decision == Decision.CRITICAL and not hard_rule_escalation:
            verdict = self.auditor.judge(event, anomaly)

        # Send alerts
        if anomaly.decision in (Decision.ALERT, Decision.CRITICAL):
            self.alerter.send(event, anomaly, verdict)

        # Update profile with learned behavior
        profile.update_profile(event)

        # Log action
        self._log_action(event, anomaly, rule_matches, seq_matches, verdict)

        # Log sequences
        if seq_matches:
            self._write_sequence_log(event, seq_matches, anomaly)

        # Log audit verdicts
        if verdict:
            self._write_audit_log(event, anomaly, verdict)

        # Log cognitive file changes (proposal 4.3)
        if (event.action_type == ActionType.FILE_WRITE
                and _is_cognitive_file(event.target)):
            matched_rule = next(
                (m.rule_id for m in rule_matches), ""
            )
            self._write_cognitive_log(event, anomaly, matched_rule)

        return anomaly

    def _log_action(self, event, anomaly, rule_matches, seq_matches, verdict) -> None:
        """Append event + result to JSONL action log."""
        try:
            self._action_log_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "event": event.to_dict(),
                "anomaly": anomaly.to_dict(),
                "rules": [{"id": m.rule_id, "name": m.rule_name} for m in rule_matches],
                "sequences": [m.pattern_name for m in seq_matches],
            }
            if verdict:
                entry["verdict"] = verdict.to_dict()

            with self._action_log_path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            logger.exception("Failed to write action log")

    def _write_sequence_log(
        self,
        event: ActionEvent,
        seq_matches: list[SequenceMatch],
        anomaly: AnomalyResult,
    ) -> None:
        """Append detected sequence anomalies to sequence.log (JSONL)."""
        try:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            # Collect the recent actions from the sequence detector window
            # that are relevant to this agent
            window_events = list(self.sequence_detector.window)
            agent_actions = [
                {"type": e.action_type.value, "target": e.target}
                for e in window_events
                if e.agent_id == event.agent_id
            ][-5:]  # Last 5 actions for context

            for match in seq_matches:
                # Compute time gap between first and last relevant action
                agent_ts = [
                    e.ts for e in window_events if e.agent_id == event.agent_id
                ]
                gap_s = 0.0
                if len(agent_ts) >= 2:
                    gap_s = (agent_ts[-1] - agent_ts[0]).total_seconds()

                entry = {
                    "ts": event.ts.isoformat(),
                    "agent": event.agent_id,
                    "pattern": match.pattern_name,
                    "actions": agent_actions,
                    "gap_s": round(gap_s, 1),
                    "score": round(anomaly.score, 2),
                    "decision": anomaly.decision.value,
                }
                with self._sequence_log_path.open("a") as f:
                    f.write(json.dumps(entry) + "\n")
        except Exception:
            logger.exception("Failed to write sequence log")

    def _write_audit_log(
        self,
        event: ActionEvent,
        anomaly: AnomalyResult,
        verdict: AuditVerdict,
    ) -> None:
        """Append Layer 3 audit results to audit.log (JSONL)."""
        try:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts": event.ts.isoformat(),
                "agent": event.agent_id,
                "action": event.action_type.value,
                "target": event.target,
                "l2_score": round(anomaly.score, 2),
                "verdict": verdict.verdict.value,
                "confidence": round(verdict.confidence, 2),
                "reason": verdict.reason,
            }
            if verdict.latency_ms is not None:
                entry["latency_ms"] = verdict.latency_ms
            with self._audit_log_path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            logger.exception("Failed to write audit log")

    def _write_cognitive_log(
        self,
        event: ActionEvent,
        anomaly: AnomalyResult,
        rule_id: str,
    ) -> None:
        """Append cognitive file changes to cognitive.log (JSONL, proposal 4.3)."""
        try:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            taint_level = self.taint_table.aggregate_taint(event.ts)
            entry = {
                "ts": event.ts.isoformat(),
                "file": Path(event.target).name,
                "agent": event.agent_id,
                "trigger_taint": f"{taint_level:.2f}",
                "decision": anomaly.decision.value,
                "rule": rule_id,
            }
            with self._cognitive_log_path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            logger.exception("Failed to write cognitive log")

    def start(self, simulate: bool = False) -> None:
        """Start the monitoring loop."""
        logger.info("WatchClaw engine starting...")
        self._running = True

        if simulate:
            self._run_simulation()
        else:
            self._run_monitoring()

    def _run_simulation(self) -> None:
        """Run with simulated events."""
        gen = SimulatedEventGenerator()
        logger.info("Running in simulation mode")

        while self._running:
            event = gen.generate_normal()
            self.process_event(event)
            time.sleep(1.0)

    def _run_monitoring(self) -> None:
        """Run with real log and filesystem monitoring."""
        log_parser = OpenClawLogParser(
            log_dir=self.config.get("log_dir", "/tmp/openclaw"),
        )
        fs_watcher = FileSystemWatcher(
            watch_dirs=self.config.get("watch_dirs"),
        )
        fs_watcher.initialize_snapshot()

        while self._running:
            # Parse new log entries
            for event in log_parser.parse_new_entries():
                self.process_event(event)

            # Check filesystem changes
            for event in fs_watcher.scan():
                self.process_event(event)

            time.sleep(self.config.get("poll_interval", 2.0))

    def stop(self) -> None:
        self._running = False
        logger.info("WatchClaw engine stopped")

    def get_profile(self, agent_id: str) -> AgentProfile | None:
        return self._profiles.get(agent_id)

    def get_profiles(self) -> dict[str, AgentProfile]:
        return dict(self._profiles)
