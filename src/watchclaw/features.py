"""Content feature extraction: entropy, API key patterns, etc."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any


def shannon_entropy(data: bytes | str) -> float:
    """Calculate Shannon entropy (0-8 range; higher = more random/likely a key).

    Accepts both bytes and str. For bytes, operates on byte values (0-255).
    For str, operates on characters.
    """
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counter.values())
    return round(entropy, 3)


# Patterns for sensitive content detection
_API_KEY_PATTERNS = [
    re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w\-]{20,}", re.IGNORECASE),
    re.compile(r"(?:sk|pk)[-_](?:live|test)[-_][\w]{20,}", re.IGNORECASE),
    re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    re.compile(r"glpat-[\w\-]{20,}"),
    re.compile(r"xox[bpsra]-[\w\-]{10,}"),
]

_EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+")
_PRIVATE_KEY_MARKERS = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
]
_PASSWORD_PATTERN = re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+")
_TOKEN_PATTERN = re.compile(r"(?i)(token|secret|api_key|apikey)\s*[=:]\s*\S+")
_BASE64_BLOCK_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_EVAL_PATTERN = re.compile(r"\b(eval|exec|compile)\s*\(")


def _is_json(text: str) -> bool:
    """Check if text is valid JSON."""
    stripped = text.strip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False
    try:
        json.loads(stripped)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def extract_content_features(content: bytes | str, file_path: str = "") -> dict[str, Any]:
    """Extract security-relevant features from content without exposing raw content.

    Accepts both bytes and str. Bytes are decoded as UTF-8 for text pattern
    matching; entropy is computed on the raw bytes for accuracy.
    """
    if isinstance(content, bytes):
        raw_bytes = content
        text = content.decode("utf-8", errors="ignore")
    else:
        raw_bytes = content.encode("utf-8")
        text = content

    api_key_count = sum(len(p.findall(text)) for p in _API_KEY_PATTERNS)
    email_count = len(_EMAIL_PATTERN.findall(text))
    ip_count = len(_IP_PATTERN.findall(text))
    url_count = len(_URL_PATTERN.findall(text))
    has_private_key = any(marker in text for marker in _PRIVATE_KEY_MARKERS)

    lines = text.splitlines()

    # Detect file type from extension
    file_type = ""
    if file_path:
        p = Path(file_path)
        suffix = p.suffix.lstrip(".")
        if suffix:
            file_type = suffix
        elif p.name.startswith("."):
            # Dotfiles like .env → use name without the dot
            file_type = p.name.lstrip(".")

    # Detect .env format (KEY=VALUE lines)
    env_lines = sum(1 for line in lines if re.match(r"^[A-Z_][A-Z0-9_]*=", line))
    has_env_format = env_lines >= 2

    return {
        "size_bytes": len(raw_bytes),
        "entropy": shannon_entropy(raw_bytes),
        # Sensitive pattern counts (no actual values exposed)
        "api_key_patterns": api_key_count,
        "email_patterns": email_count,
        "ip_patterns": ip_count,
        "url_patterns": url_count,
        "private_key_markers": has_private_key,
        "password_patterns": len(_PASSWORD_PATTERN.findall(text)),
        "token_patterns": len(_TOKEN_PATTERN.findall(text)),
        # Structure features
        "file_type": file_type,
        "line_count": len(lines),
        "has_json_structure": _is_json(text),
        "has_env_format": has_env_format,
        # Suspicious content features
        "base64_blocks": len(_BASE64_BLOCK_PATTERN.findall(text)),
        "shell_pipes": text.count("|"),
        "eval_calls": len(_EVAL_PATTERN.findall(text)),
    }
