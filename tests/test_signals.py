"""Round 5 tests: R2 audit fixes — D1, D2, D6, D8."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from watchclaw.engine import WatchClawEngine
from watchclaw.models import ActionEvent, ActionType, AgentProfile, Decision
from watchclaw.scorer import (
    AnomalyScorer,
    KNOWN_BAD_DOMAINS,
    _is_newly_registered_heuristic,
)
from watchclaw.taint import TaintTable


def _make_engine(tmp_path: Path) -> WatchClawEngine:
    config = {
        "action_log": str(tmp_path / "action.log"),
        "taint_half_life": 300.0,
    }
    engine = WatchClawEngine(config=config)
    rules_path = Path(__file__).parent.parent / "configs" / "default-rules.yaml"
    if rules_path.exists():
        engine.rule_engine.load_rules(rules_path)
    return engine


def _make_event(
    action_type: ActionType = ActionType.FILE_READ,
    target: str = "src/main.py",
    agent_id: str = "test-agent",
    args: dict | None = None,
    ts: datetime | None = None,
) -> ActionEvent:
    return ActionEvent(
        ts=ts or datetime.now(timezone.utc),
        session_id="test",
        agent_id=agent_id,
        action_type=action_type,
        target=target,
        args=args or {},
        source="test",
    )


# ── D1: resource_anomaly additive formula ────────────────────────────


class TestResourceAnomalyFormula:
    """D1: resource_anomaly should use additive 0.4 (unknown) + 0.6 (sensitive)."""

    def test_unknown_sensitive_file_scores_1_0(self):
        """Unknown + sensitive file → 0.4 + 0.6 = 1.0."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event(
            action_type=ActionType.FILE_READ,
            target=".env",  # sensitivity=0.9, unknown
        )
        result = scorer.score(event, profile)
        resource_sig = next(s for s in result.signals if s.name == "resource_anomaly")
        assert resource_sig.value == 1.0

    def test_known_sensitive_file_scores_0_6(self):
        """Known + sensitive file → 0.0 + 0.6 = 0.6."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        profile.common_files[".env"] = 10  # known
        event = _make_event(
            action_type=ActionType.FILE_READ,
            target=".env",  # sensitivity=0.9, known
        )
        result = scorer.score(event, profile)
        resource_sig = next(s for s in result.signals if s.name == "resource_anomaly")
        assert resource_sig.value == 0.6

    def test_unknown_nonsensitive_file_scores_0_4(self):
        """Unknown + non-sensitive file → 0.4 + 0.0 = 0.4."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event(
            action_type=ActionType.FILE_READ,
            target="README.md",  # sensitivity=0.1, unknown
        )
        result = scorer.score(event, profile)
        resource_sig = next(s for s in result.signals if s.name == "resource_anomaly")
        assert resource_sig.value == 0.4

    def test_known_nonsensitive_file_scores_0(self):
        """Known + non-sensitive file → 0.0 + 0.0 = 0.0."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        profile.common_files["README.md"] = 5  # known
        event = _make_event(
            action_type=ActionType.FILE_READ,
            target="README.md",  # sensitivity=0.1, known
        )
        result = scorer.score(event, profile)
        resource_sig = next(s for s in result.signals if s.name == "resource_anomaly")
        assert resource_sig.value == 0.0

    def test_non_file_action_scores_zero(self):
        """EXEC/WEB_FETCH should not trigger resource_anomaly additive logic."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event(
            action_type=ActionType.EXEC,
            target="ls -la",
        )
        result = scorer.score(event, profile)
        resource_sig = next(s for s in result.signals if s.name == "resource_anomaly")
        assert resource_sig.value == 0.0

    def test_file_write_also_applies(self):
        """FILE_WRITE should also use the additive formula."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event(
            action_type=ActionType.FILE_WRITE,
            target="secrets.yaml",  # sensitivity=0.95 via _SENSITIVE_NAMES
        )
        result = scorer.score(event, profile)
        resource_sig = next(s for s in result.signals if s.name == "resource_anomaly")
        # Unknown (0.4) + sensitive (0.6) = 1.0
        assert resource_sig.value == 1.0


# ── D2: destination_anomaly newly_registered tier ─────────────────────


class TestDestinationAnomalyNewlyRegistered:
    """D2: destination_anomaly should score unknown + newly_registered as 0.9."""

    def test_newly_registered_heuristic_suspicious_tld(self):
        """Domains on suspicious TLDs should be flagged as newly registered."""
        assert _is_newly_registered_heuristic("malware.xyz")
        assert _is_newly_registered_heuristic("phish.tk")
        assert _is_newly_registered_heuristic("evil.ml")
        assert _is_newly_registered_heuristic("bad.top")

    def test_newly_registered_heuristic_normal_tld(self):
        """Normal TLDs should not be flagged."""
        assert not _is_newly_registered_heuristic("google.com")
        assert not _is_newly_registered_heuristic("github.io")
        assert not _is_newly_registered_heuristic("example.org")

    def test_unknown_newly_registered_scores_0_9(self):
        """Unknown domain on suspicious TLD → 0.4 + 0.5 = 0.9."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event(
            action_type=ActionType.WEB_FETCH,
            target="https://evil-data.xyz/exfil",
            args={"domain": "evil-data.xyz"},
        )
        result = scorer.score(event, profile)
        dest_sig = next(s for s in result.signals if s.name == "destination_anomaly")
        assert dest_sig.value == 0.9

    def test_unknown_normal_tld_scores_0_4(self):
        """Unknown domain on normal TLD → 0.4 only."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event(
            action_type=ActionType.WEB_FETCH,
            target="https://some-unknown.com/api",
            args={"domain": "some-unknown.com"},
        )
        result = scorer.score(event, profile)
        dest_sig = next(s for s in result.signals if s.name == "destination_anomaly")
        assert dest_sig.value == 0.4

    def test_known_bad_still_scores_1_0(self):
        """Known-bad domains should still score 1.0 (not affected by newly_registered)."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        event = _make_event(
            action_type=ActionType.WEB_FETCH,
            target="https://evil-exfil.com/upload",
            args={"domain": "evil-exfil.com"},
        )
        result = scorer.score(event, profile)
        dest_sig = next(s for s in result.signals if s.name == "destination_anomaly")
        assert dest_sig.value == 1.0

    def test_known_domain_scores_0_1(self):
        """Known domains should still score 0.1."""
        scorer = AnomalyScorer()
        profile = AgentProfile(agent_id="test")
        profile.common_domains["api.github.com"] = 50  # known
        event = _make_event(
            action_type=ActionType.WEB_FETCH,
            target="https://api.github.com/repos",
            args={"domain": "api.github.com"},
        )
        result = scorer.score(event, profile)
        dest_sig = next(s for s in result.signals if s.name == "destination_anomaly")
        assert dest_sig.value == 0.1


# ── D6: Layer 2 skipped for hard-rule BLOCKs ─────────────────────────


class TestLayerTwoSkipOnBlock:
    """D6: Hard-rule BLOCK events should skip Layer 2 scoring."""

    def test_hard_block_skips_scoring(self, tmp_path):
        """WC-HARD-001 (watchclaw modification) should skip Layer 2."""
        engine = _make_engine(tmp_path)
        result = engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="s1",
            agent_id="rogue",
            action_type=ActionType.FILE_WRITE,
            target="/home/user/watchclaw/engine.py",
            source="test",
        ))
        # Hard rule CRITICAL
        assert result.decision == Decision.CRITICAL
        assert result.score >= 0.9
        # No signals computed (Layer 2 skipped)
        assert result.signals == []

    def test_non_block_still_runs_scoring(self, tmp_path):
        """Normal events should still get full Layer 2 scoring."""
        engine = _make_engine(tmp_path)
        result = engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="s2",
            agent_id="melody",
            action_type=ActionType.FILE_READ,
            target="README.md",
            source="test",
        ))
        # Should have 6 signals from Layer 2
        assert len(result.signals) == 6

    def test_hard_block_no_audit_log(self, tmp_path):
        """Hard-rule BLOCK should not create audit.log (no LLM needed)."""
        engine = _make_engine(tmp_path)
        engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="s3",
            agent_id="rogue",
            action_type=ActionType.FILE_WRITE,
            target="/home/user/watchclaw/engine.py",
            source="test",
        ))
        audit_log = tmp_path / "audit.log"
        assert not audit_log.exists()


# ── D8: cognitive.log ─────────────────────────────────────────────────


class TestCognitiveLog:
    """D8: cognitive.log should record identity/cognitive file changes."""

    def test_cognitive_log_created_on_soul_write(self, tmp_path):
        """Writing to SOUL.md should create cognitive.log entry."""
        engine = _make_engine(tmp_path)
        engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="c1",
            agent_id="melody",
            action_type=ActionType.FILE_WRITE,
            target="SOUL.md",
            source="test",
        ))

        cog_log = tmp_path / "cognitive.log"
        assert cog_log.exists(), "cognitive.log should be created on cognitive file write"

        lines = cog_log.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["file"] == "SOUL.md"
        assert entry["agent"] == "melody"
        assert "decision" in entry
        assert "ts" in entry

    def test_cognitive_log_on_identity_md(self, tmp_path):
        """Writing to IDENTITY.md should also log."""
        engine = _make_engine(tmp_path)
        engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="c2",
            agent_id="judy",
            action_type=ActionType.FILE_WRITE,
            target="/workspace/IDENTITY.md",
            source="test",
        ))

        cog_log = tmp_path / "cognitive.log"
        assert cog_log.exists()
        entry = json.loads(cog_log.read_text().strip())
        assert entry["file"] == "IDENTITY.md"

    def test_cognitive_log_not_created_for_normal_file(self, tmp_path):
        """Writing to a normal file should not create cognitive.log."""
        engine = _make_engine(tmp_path)
        engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="c3",
            agent_id="melody",
            action_type=ActionType.FILE_WRITE,
            target="src/main.py",
            source="test",
        ))

        cog_log = tmp_path / "cognitive.log"
        assert not cog_log.exists()

    def test_cognitive_log_not_created_for_read(self, tmp_path):
        """Reading a cognitive file should not log (only writes)."""
        engine = _make_engine(tmp_path)
        engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="c4",
            agent_id="melody",
            action_type=ActionType.FILE_READ,
            target="SOUL.md",
            source="test",
        ))

        cog_log = tmp_path / "cognitive.log"
        assert not cog_log.exists()

    def test_cognitive_log_includes_rule(self, tmp_path):
        """If a hard rule matched, cognitive.log should include the rule ID."""
        engine = _make_engine(tmp_path)
        engine.process_event(ActionEvent(
            ts=datetime.now(timezone.utc),
            session_id="c5",
            agent_id="rogue",
            action_type=ActionType.FILE_WRITE,
            target="SOUL.md",
            source="test",
        ))

        cog_log = tmp_path / "cognitive.log"
        assert cog_log.exists()
        entry = json.loads(cog_log.read_text().strip())
        # WC-HARD-002 is the cognitive file write alert rule
        assert entry["rule"] == "WC-HARD-002"

    def test_cognitive_log_jsonl_format(self, tmp_path):
        """Multiple cognitive writes should produce valid JSONL."""
        engine = _make_engine(tmp_path)
        now = datetime.now(timezone.utc)

        for i, target in enumerate(["SOUL.md", "CLAUDE.md", "MEMORY.md"]):
            engine.process_event(ActionEvent(
                ts=now + timedelta(seconds=i),
                session_id=f"c6-{i}",
                agent_id="melody",
                action_type=ActionType.FILE_WRITE,
                target=target,
                source="test",
            ))

        cog_log = tmp_path / "cognitive.log"
        lines = cog_log.read_text().strip().splitlines()
        assert len(lines) == 3
        files = [json.loads(line)["file"] for line in lines]
        assert files == ["SOUL.md", "CLAUDE.md", "MEMORY.md"]

    def test_all_four_log_paths(self, tmp_path):
        """Engine should have paths for all four log files."""
        engine = _make_engine(tmp_path)
        assert engine._action_log_path.name == "action.log"
        assert engine._sequence_log_path.name == "sequence.log"
        assert engine._audit_log_path.name == "audit.log"
        assert engine._cognitive_log_path.name == "cognitive.log"
        # All in same directory
        assert engine._cognitive_log_path.parent == engine._action_log_path.parent
