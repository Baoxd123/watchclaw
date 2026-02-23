"""Tests for Layer 3: LLM Auditor."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from watchclaw.auditor import (
    AUDITOR_SYSTEM_PROMPT,
    LLMAuditor,
    _extract_content_features_if_available,
    is_sensitive_path,
    sanitize_path,
)
from watchclaw.models import (
    ActionEvent,
    ActionType,
    AnomalyResult,
    AuditVerdict,
    Decision,
    Signal,
    Verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**overrides) -> ActionEvent:
    defaults = dict(
        ts=datetime(2025, 6, 15, 14, 30, 0, tzinfo=timezone.utc),
        session_id="sess-1",
        agent_id="melody",
        action_type=ActionType.FILE_WRITE,
        target="/home/user/project/.env",
        source="test",
    )
    defaults.update(overrides)
    return ActionEvent(**defaults)


def _make_anomaly(score: float = 0.85, signals: list | None = None) -> AnomalyResult:
    if signals is None:
        signals = [
            Signal(name="time_anomaly", value=0.6, weight=0.2, reason="unusual hour"),
            Signal(name="taint_flow", value=0.8, weight=0.15, reason="high taint"),
        ]
    return AnomalyResult(score=score, signals=signals, decision=Decision.CRITICAL)


# ---------------------------------------------------------------------------
# AUDITOR_SYSTEM_PROMPT
# ---------------------------------------------------------------------------

class TestAuditorSystemPrompt:
    def test_prompt_defined_and_nonempty(self):
        assert AUDITOR_SYSTEM_PROMPT
        assert len(AUDITOR_SYSTEM_PROMPT) > 100

    def test_prompt_mentions_verdicts(self):
        for v in ("SAFE", "SUSPICIOUS", "MALICIOUS"):
            assert v in AUDITOR_SYSTEM_PROMPT

    def test_prompt_forbids_tools(self):
        assert "NO tools" in AUDITOR_SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Audit context — NO raw content
# ---------------------------------------------------------------------------

class TestBuildAuditContext:
    def test_context_has_required_keys(self):
        auditor = LLMAuditor()
        ctx = auditor._build_audit_context(_make_event(), _make_anomaly())
        assert "agent_id" in ctx
        assert "action" in ctx
        assert "anomaly" in ctx
        assert "context" in ctx

    def test_context_excludes_raw_content(self):
        event = _make_event(args={"content": "SECRET_KEY=abc123"})
        auditor = LLMAuditor()
        ctx = auditor._build_audit_context(event, _make_anomaly())
        ctx_str = json.dumps(ctx)
        # Raw content must NOT appear in the context string
        assert "SECRET_KEY=abc123" not in ctx_str
        # But content features should be present
        assert ctx["content_features"] is not None
        assert "api_key_patterns" in ctx["content_features"]

    def test_context_filters_low_signals(self):
        signals = [
            Signal(name="low_sig", value=0.1, weight=0.1, reason="low"),
            Signal(name="high_sig", value=0.5, weight=0.2, reason="high"),
        ]
        auditor = LLMAuditor()
        ctx = auditor._build_audit_context(_make_event(), _make_anomaly(signals=signals))
        sig_names = [s["name"] for s in ctx["anomaly"]["signals"]]
        assert "low_sig" not in sig_names
        assert "high_sig" in sig_names

    def test_context_includes_hour_and_sensitivity(self):
        event = _make_event(target="/home/user/.ssh/id_rsa")
        auditor = LLMAuditor()
        ctx = auditor._build_audit_context(event, _make_anomaly())
        assert ctx["context"]["hour"] == 14
        assert ctx["context"]["is_sensitive_target"] is True

    def test_content_features_none_when_no_content(self):
        event = _make_event(args={}, result_summary="")
        auditor = LLMAuditor()
        ctx = auditor._build_audit_context(event, _make_anomaly())
        assert ctx["content_features"] is None


# ---------------------------------------------------------------------------
# Fallback (no API key)
# ---------------------------------------------------------------------------

class TestJudgeFallback:
    def test_fallback_high_score_malicious(self):
        auditor = LLMAuditor(api_key=None)
        result = auditor.judge(_make_event(), _make_anomaly(score=0.85))
        assert isinstance(result, AuditVerdict)
        assert result.verdict == Verdict.MALICIOUS

    def test_fallback_medium_score_suspicious(self):
        auditor = LLMAuditor(api_key=None)
        result = auditor.judge(_make_event(), _make_anomaly(score=0.65))
        assert result.verdict == Verdict.SUSPICIOUS

    def test_fallback_low_score_safe(self):
        auditor = LLMAuditor(api_key=None)
        result = auditor.judge(_make_event(), _make_anomaly(score=0.3))
        assert result.verdict == Verdict.SAFE

    def test_fallback_returns_valid_confidence(self):
        auditor = LLMAuditor(api_key=None)
        result = auditor.judge(_make_event(), _make_anomaly(score=0.5))
        assert 0.0 <= result.confidence <= 1.0

    @patch.dict("os.environ", {}, clear=True)
    def test_no_env_key_uses_stub(self):
        """Without ANTHROPIC_API_KEY in env, should use stub path."""
        auditor = LLMAuditor(api_key=None)
        result = auditor.judge(_make_event(), _make_anomaly(score=0.9))
        assert isinstance(result, AuditVerdict)


# ---------------------------------------------------------------------------
# Anthropic mock
# ---------------------------------------------------------------------------

class TestJudgeAnthropic:
    def test_anthropic_success(self):
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text='{"verdict":"SUSPICIOUS","confidence":0.75,"reason":"Unusual file access"}')
        ]
        with patch.dict("os.environ", {}, clear=True):
            with patch("watchclaw.auditor.anthropic") as mock_mod:
                mock_mod.Anthropic.return_value.messages.create.return_value = mock_response
                auditor = LLMAuditor(api_key="test-key-123")
                result = auditor.judge(_make_event(), _make_anomaly(score=0.85))
        assert result.verdict == Verdict.SUSPICIOUS
        assert result.confidence == 0.75
        assert result.reason == "Unusual file access"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0

    def test_anthropic_malicious_verdict(self):
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text='{"verdict":"MALICIOUS","confidence":0.95,"reason":"Data exfiltration pattern"}')
        ]
        with patch.dict("os.environ", {}, clear=True):
            with patch("watchclaw.auditor.anthropic") as mock_mod:
                mock_mod.Anthropic.return_value.messages.create.return_value = mock_response
                auditor = LLMAuditor(api_key="test-key")
                result = auditor.judge(_make_event(), _make_anomaly(score=0.9))
        assert result.verdict == Verdict.MALICIOUS
        assert result.confidence == 0.95

    def test_anthropic_safe_verdict(self):
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text='{"verdict":"SAFE","confidence":0.9,"reason":"Normal operation"}')
        ]
        with patch.dict("os.environ", {}, clear=True):
            with patch("watchclaw.auditor.anthropic") as mock_mod:
                mock_mod.Anthropic.return_value.messages.create.return_value = mock_response
                auditor = LLMAuditor(api_key="test-key")
                result = auditor.judge(_make_event(), _make_anomaly(score=0.7))
        assert result.verdict == Verdict.SAFE

    def test_anthropic_uses_system_prompt(self):
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text='{"verdict":"SAFE","confidence":0.8,"reason":"ok"}')
        ]
        with patch.dict("os.environ", {}, clear=True):
            with patch("watchclaw.auditor.anthropic") as mock_mod:
                mock_client = mock_mod.Anthropic.return_value
                mock_client.messages.create.return_value = mock_response
                auditor = LLMAuditor(api_key="test-key")
                auditor.judge(_make_event(), _make_anomaly())

                call_kwargs = mock_client.messages.create.call_args.kwargs
                assert call_kwargs["system"] == AUDITOR_SYSTEM_PROMPT

    def test_anthropic_sends_json_context(self):
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text='{"verdict":"SAFE","confidence":0.8,"reason":"ok"}')
        ]
        with patch.dict("os.environ", {}, clear=True):
            with patch("watchclaw.auditor.anthropic") as mock_mod:
                mock_client = mock_mod.Anthropic.return_value
                mock_client.messages.create.return_value = mock_response
                auditor = LLMAuditor(api_key="test-key")
                auditor.judge(_make_event(), _make_anomaly())

                call_kwargs = mock_client.messages.create.call_args.kwargs
                msg_content = call_kwargs["messages"][0]["content"]
                parsed = json.loads(msg_content)
                assert "agent_id" in parsed
                assert "anomaly" in parsed


# ---------------------------------------------------------------------------
# Error handling — API failure falls back to stub
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_api_exception_falls_back(self):
        with patch.dict("os.environ", {}, clear=True):
            with patch("watchclaw.auditor.anthropic") as mock_mod:
                mock_mod.Anthropic.return_value.messages.create.side_effect = RuntimeError("API down")
                auditor = LLMAuditor(api_key="test-key")
                result = auditor.judge(_make_event(), _make_anomaly(score=0.85))
        # Should fallback to stub, not crash
        assert isinstance(result, AuditVerdict)
        assert result.verdict == Verdict.MALICIOUS  # stub gives MALICIOUS for 0.85

    def test_invalid_json_response_falls_back(self):
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="not valid json")]
        with patch.dict("os.environ", {}, clear=True):
            with patch("watchclaw.auditor.anthropic") as mock_mod:
                mock_mod.Anthropic.return_value.messages.create.return_value = mock_response
                auditor = LLMAuditor(api_key="test-key")
                result = auditor.judge(_make_event(), _make_anomaly(score=0.65))
        assert isinstance(result, AuditVerdict)
        assert result.verdict == Verdict.SUSPICIOUS  # stub for 0.65

    def test_env_key_used_when_no_init_key(self):
        """ANTHROPIC_API_KEY env var should be picked up."""
        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text='{"verdict":"SAFE","confidence":0.9,"reason":"ok"}')
        ]
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "env-key-xyz"}, clear=False):
            with patch("watchclaw.auditor.anthropic") as mock_mod:
                mock_mod.Anthropic.return_value.messages.create.return_value = mock_response
                auditor = LLMAuditor(api_key=None)
                result = auditor.judge(_make_event(), _make_anomaly())
        assert result.verdict == Verdict.SAFE
        mock_mod.Anthropic.assert_called_once_with(api_key="env-key-xyz")


# ---------------------------------------------------------------------------
# Path utilities
# ---------------------------------------------------------------------------

class TestPathUtilities:
    @pytest.mark.parametrize("path,expected", [
        ("/home/user/.ssh/id_rsa", True),
        ("/Users/dev/.aws/credentials", True),
        ("/project/.env", True),
        ("/project/.env.local", True),
        ("src/main.py", False),
        ("README.md", False),
        ("/project/secrets.yaml", True),
        ("/project/config/CLAUDE.md", True),
        ("/home/user/.gnupg/secring.gpg", True),
    ])
    def test_is_sensitive_path(self, path, expected):
        assert is_sensitive_path(path) == expected

    def test_sanitize_path_strips_home(self):
        assert sanitize_path("/home/user/project/file.py") == "project/file.py"
        assert sanitize_path("/Users/dev/work/src/main.py") == "work/src/main.py"

    def test_sanitize_path_preserves_relative(self):
        assert sanitize_path("src/main.py") == "src/main.py"


# ---------------------------------------------------------------------------
# AuditVerdict.latency_ms
# ---------------------------------------------------------------------------

class TestAuditVerdictLatency:
    def test_latency_ms_default_none(self):
        v = AuditVerdict(verdict=Verdict.SAFE, confidence=0.8, reason="ok")
        assert v.latency_ms is None

    def test_latency_ms_in_to_dict(self):
        v = AuditVerdict(verdict=Verdict.SAFE, confidence=0.8, reason="ok", latency_ms=42.5)
        d = v.to_dict()
        assert d["latency_ms"] == 42.5

    def test_latency_ms_omitted_when_none(self):
        v = AuditVerdict(verdict=Verdict.SAFE, confidence=0.8, reason="ok")
        d = v.to_dict()
        assert "latency_ms" not in d
