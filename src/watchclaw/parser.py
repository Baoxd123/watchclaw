"""Multi-source event ingestion: log parsing, file system monitoring, simulation."""

from __future__ import annotations

import json
import logging
import os
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

from watchclaw.models import ActionEvent, ActionType, TaintLevel

logger = logging.getLogger(__name__)

# --- Exec command analysis helpers (used by parser, scorer, taint) ---

import re as _re_module

_RE_FILE_READ_CMD = _re_module.compile(
    r"^(?:cat|head|tail|less|more|grep|awk|sed|cut)\b"
)
_RE_URL_IN_CMD = _re_module.compile(r"https?://[^\s|>\"']+")
_RE_CURL_WGET_CMD = _re_module.compile(r"^(?:curl|wget)\b")
_RE_DOMAIN_FROM_URL = _re_module.compile(r"https?://([^/\s:]+)")


def _extract_file_from_exec(cmd: str) -> str | None:
    """Extract file path from exec commands that read files.

    Recognizes: cat, head, tail, less, more, grep, awk, sed, cut.
    Returns the file path argument, or None.
    """
    cmd = cmd.strip()
    if not _RE_FILE_READ_CMD.match(cmd):
        return None
    parts = cmd.split()
    if len(parts) < 2:
        return None
    # Search from the end for a path-like argument (skip flags)
    for part in reversed(parts[1:]):
        if part.startswith("-"):
            continue
        # Absolute or home-relative paths
        if part.startswith(("/", "~")):
            return part
        # Relative paths with directory separator
        if "/" in part:
            return part
        # Known sensitive file names or extensions
        if _re_module.search(
            r"(?:credentials|password|secret|key|token|id_rsa|id_ed25519"
            r"|\.env|\.pem|\.p12|\.json|\.yaml|\.yml"
            r"|SOUL\.md|MEMORY\.md|USER\.md|\.ssh)",
            part,
            _re_module.IGNORECASE,
        ):
            return part
    return None


def _extract_url_from_exec(cmd: str) -> str | None:
    """Extract URL from exec commands (curl, wget, or any URL in command).

    Returns the first http(s) URL found, or None.
    """
    m = _RE_URL_IN_CMD.search(cmd)
    if m:
        url = m.group(0).rstrip(")")
        return url
    return None


class OpenClawLogParser:
    """Parse OpenClaw gateway JSONL log files.

    Handles the real OpenClaw log format where each line is JSON with:
      - "0": primary message string
      - "1": secondary message string (optional)
      - "_meta": metadata dict with name, date, logLevelName, etc.
      - "time": ISO timestamp

    Extracts events from:
      1. Tool call start/end: "embedded run tool start: runId=... tool=<type> ..."
      2. Tool errors: "[tools] <type> failed: <message>"
      3. Agent sessions: "sessionKey=agent:<name>:..." for runId->agent mapping
    """

    # Map OpenClaw tool names to ActionType
    _TOOL_TYPE_MAP: dict[str, ActionType] = {
        "exec": ActionType.EXEC,
        "process": ActionType.EXEC,
        "read": ActionType.FILE_READ,
        "write": ActionType.FILE_WRITE,
        "edit": ActionType.FILE_WRITE,
        "web_fetch": ActionType.WEB_FETCH,
        "web_search": ActionType.WEB_FETCH,
        "message": ActionType.MESSAGE_SEND,
        "cron": ActionType.TOOL_CALL,
        "gateway": ActionType.TOOL_CALL,
        "agents_list": ActionType.TOOL_CALL,
        "memory_search": ActionType.TOOL_CALL,
        "memory_get": ActionType.TOOL_CALL,
        "session_status": ActionType.TOOL_CALL,
    }

    import re as _re
    _RE_TOOL_START = _re.compile(
        r"embedded run tool start: runId=([a-f0-9-]+) tool=(\w+) toolCallId=(\S+)"
    )
    _RE_TOOL_END = _re.compile(
        r"embedded run tool end: runId=([a-f0-9-]+) tool=(\w+)"
    )
    _RE_RUN_START = _re.compile(
        r"embedded run start: runId=([a-f0-9-]+) sessionId=([a-f0-9-]+)"
    )
    _RE_SESSION_KEY = _re.compile(r"sessionKey=agent:(\w+)")
    _RE_RUN_ID = _re.compile(r"runId=([a-f0-9-]+)")
    _RE_SESSION_ID = _re.compile(r"sessionId=([a-f0-9-]+)")
    _RE_TOOL_ERROR = _re.compile(r"^\[tools\]\s+(\w+)\s+failed:\s*(.*)")

    # Extract subsystem from _meta.name JSON
    _RE_ELEVATED_CMD = _re.compile(r"^elevated command (.+)")
    # Infer agent from workspace path: /.../.openclaw/workspace-<agent>/...
    _RE_WORKSPACE_AGENT = _re.compile(r"/\.openclaw/workspace-(\w+)/")

    def __init__(self, log_dir: str = "/tmp/openclaw") -> None:
        self.log_dir = Path(log_dir)
        self._file_positions: dict[str, int] = {}
        # State for correlating runId -> agent across log lines
        self._run_to_agent: dict[str, str] = {}
        self._session_to_agent: dict[str, str] = {}
        self._run_to_session: dict[str, str] = {}
        # Track sessionKey-based agent names (for sessionId=unknown cases)
        self._session_key_to_agent: dict[str, str] = {}
        # Track last tool start context for exec subsystem correlation
        self._last_tool_run_id: str | None = None
        # Pending exec event: deferred until we see exec subsystem or next event
        self._pending_exec: ActionEvent | None = None

    def get_log_files(self) -> list[Path]:
        """Get available log files sorted by date."""
        if not self.log_dir.exists():
            return []
        return sorted(self.log_dir.glob("openclaw-*.log"))

    def parse_file(self, path: Path, from_position: int = 0) -> Generator[ActionEvent, None, None]:
        """Parse a JSONL log file from a given position."""
        try:
            with path.open() as f:
                f.seek(from_position)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        events = self._parse_log_entry(data)
                        yield from events
                    except (json.JSONDecodeError, KeyError, ValueError) as e:
                        logger.debug("Skipping malformed log line: %s", e)
                # Flush any pending exec at end of file
                if self._pending_exec is not None:
                    yield self._pending_exec
                    self._pending_exec = None
                self._file_positions[str(path)] = f.tell()
        except FileNotFoundError:
            logger.warning("Log file not found: %s", path)

    def parse_new_entries(self) -> Generator[ActionEvent, None, None]:
        """Parse only new entries since last read."""
        for path in self.get_log_files():
            pos = self._file_positions.get(str(path), 0)
            yield from self.parse_file(path, from_position=pos)

    def _extract_ts(self, data: dict) -> datetime | None:
        """Extract timestamp from a log entry."""
        ts_str = (
            data.get("_meta", {}).get("date")
            or data.get("time")
            or data.get("timestamp")
            or data.get("ts")
        )
        if not ts_str:
            return None
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts
        except (ValueError, AttributeError):
            return None

    def _resolve_agent(self, run_id: str) -> str:
        """Resolve agent name from a runId using cached mappings."""
        if run_id in self._run_to_agent:
            return self._run_to_agent[run_id]
        session_id = self._run_to_session.get(run_id)
        if session_id and session_id in self._session_to_agent:
            agent = self._session_to_agent[session_id]
            self._run_to_agent[run_id] = agent
            return agent
        return "unknown"

    def _update_session_mappings(self, msg: str) -> None:
        """Update runId/session/agent correlation state from a message."""
        # "embedded run start: runId=... sessionId=..."
        m = self._RE_RUN_START.search(msg)
        if m:
            self._run_to_session[m.group(1)] = m.group(2)

        # "sessionKey=agent:<name>:..."
        sk = self._RE_SESSION_KEY.search(msg)
        if sk:
            agent_name = sk.group(1)
            # Store by full sessionKey pattern for fallback resolution
            # Extract full sessionKey for caching
            import re as _re
            sk_full = _re.search(r"sessionKey=(agent:\w+:\S+)", msg)
            if sk_full:
                self._session_key_to_agent[sk_full.group(1)] = agent_name
            # Try to associate with runId or sessionId in same message
            rid = self._RE_RUN_ID.search(msg)
            if rid:
                self._run_to_agent[rid.group(1)] = agent_name
            sid = self._RE_SESSION_ID.search(msg)
            if sid and sid.group(1) != "unknown":
                self._session_to_agent[sid.group(1)] = agent_name
                # Back-fill any runIds that map to this session
                for r, s in self._run_to_session.items():
                    if s == sid.group(1):
                        self._run_to_agent[r] = agent_name

    def _extract_subsystem(self, data: dict) -> str | None:
        """Extract subsystem from _meta.name JSON field."""
        meta_name = data.get("_meta", {}).get("name", "")
        if isinstance(meta_name, str) and meta_name.startswith("{"):
            try:
                return json.loads(meta_name).get("subsystem")
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass
        return None

    def _infer_agent_from_path(self, path: str) -> str | None:
        """Infer agent name from workspace path like /.../.openclaw/workspace-melody/..."""
        m = self._RE_WORKSPACE_AGENT.search(path)
        return m.group(1) if m else None

    def _flush_pending_exec(self) -> list[ActionEvent]:
        """Flush any pending exec event that wasn't enriched by an exec subsystem line."""
        if self._pending_exec is not None:
            event = self._pending_exec
            self._pending_exec = None
            return [event]
        return []

    @staticmethod
    def _enrich_exec_event(event: ActionEvent) -> list[ActionEvent]:
        """Post-process an exec event: reclassify file reads and URL fetches.

        - cat/head/tail/less/more/grep/awk/sed/cut with a file → FILE_READ
        - curl/wget as primary command with a URL → WEB_FETCH
        """
        cmd = event.target
        if not cmd or cmd in ("exec", "process"):
            return [event]

        # Check for file-reading commands
        file_path = _extract_file_from_exec(cmd)
        if file_path:
            event.action_type = ActionType.FILE_READ
            event.args["original_cmd"] = cmd
            event.target = file_path
            return [event]

        # Check for curl/wget as primary command → reclassify as WEB_FETCH
        url = _extract_url_from_exec(cmd)
        if url and _RE_CURL_WGET_CMD.match(cmd.strip()):
            domain_match = _RE_DOMAIN_FROM_URL.search(url)
            domain = domain_match.group(1) if domain_match else ""
            event.action_type = ActionType.WEB_FETCH
            event.args["original_cmd"] = cmd
            event.args["domain"] = domain
            event.target = url
            return [event]

        return [event]

    def _parse_log_entry(self, data: dict) -> list[ActionEvent]:
        """Parse a real OpenClaw log entry, returning 0 or more ActionEvents."""
        msg0 = data.get("0", "")
        msg1 = data.get("1", "")
        # Fields can sometimes be dicts or other non-string types
        if not isinstance(msg0, str):
            msg0 = str(msg0)
        if not isinstance(msg1, str):
            msg1 = str(msg1)

        # Always update session mappings from any message
        if msg1:
            self._update_session_mappings(msg1)
        if msg0:
            self._update_session_mappings(msg0)

        ts = self._extract_ts(data)
        if ts is None:
            return []

        events: list[ActionEvent] = []
        subsystem = self._extract_subsystem(data)

        # 0. Exec subsystem: actual command content ("elevated command <cmd>")
        # These lines appear between tool start and tool end for exec tools.
        # They REPLACE the pending exec event with enriched target.
        if subsystem == "exec" and msg1:
            cmd = msg1
            m_cmd = self._RE_ELEVATED_CMD.match(cmd)
            if m_cmd:
                cmd = m_cmd.group(1)
            # Use pending exec context if available, otherwise resolve from last runId
            if self._pending_exec is not None:
                # Enrich the pending exec event with the actual command
                self._pending_exec.target = cmd
                event = self._pending_exec
                self._pending_exec = None
                return self._enrich_exec_event(event)
            # Fallback: create event from scratch
            run_id = self._last_tool_run_id or "unknown"
            agent_id = self._resolve_agent(run_id) if run_id != "unknown" else "unknown"
            if agent_id == "unknown":
                inferred = self._infer_agent_from_path(cmd)
                if inferred:
                    agent_id = inferred
            fallback_event = ActionEvent(
                ts=ts,
                session_id=run_id,
                agent_id=agent_id,
                action_type=ActionType.EXEC,
                target=cmd,
                args={"tool": "exec"},
                source="openclaw_log",
            )
            events.extend(self._enrich_exec_event(fallback_event))
            return events

        # 1. Tool start events: "embedded run tool start: runId=... tool=<type> ..."
        m = self._RE_TOOL_START.search(msg1)
        if m:
            run_id, tool_name, tool_call_id = m.group(1), m.group(2), m.group(3)
            self._last_tool_run_id = run_id
            action_type = self._TOOL_TYPE_MAP.get(tool_name, ActionType.TOOL_CALL)
            agent_id = self._resolve_agent(run_id)
            event = ActionEvent(
                ts=ts,
                session_id=run_id,
                agent_id=agent_id,
                action_type=action_type,
                target=tool_name,
                args={"tool_call_id": tool_call_id, "tool": tool_name},
                source="openclaw_log",
            )
            # For exec/process, defer emission - an exec subsystem line may follow
            # with the actual command. If not, we'll flush on next event or end-of-file.
            if tool_name in ("exec", "process"):
                flushed = self._flush_pending_exec()  # flush previous pending
                self._pending_exec = event
                return flushed
            # For other tools, flush any pending exec first, then emit
            flushed = self._flush_pending_exec()
            flushed.append(event)
            return flushed

        # 2. Tool error events: "[tools] <type> failed: <message>"
        m = self._RE_TOOL_ERROR.search(msg0)
        if m:
            tool_name = m.group(1)
            error_msg = m.group(2)
            action_type = self._TOOL_TYPE_MAP.get(tool_name, ActionType.TOOL_CALL)
            target = tool_name
            if tool_name in ("read", "write", "edit") and "/" in error_msg:
                import re as _re
                path_match = _re.search(r"['\"](/[^'\"]+)['\"]", error_msg)
                if path_match:
                    target = path_match.group(1)
            # Resolve agent from last tool run or from path
            agent_id = "unknown"
            if self._last_tool_run_id:
                agent_id = self._resolve_agent(self._last_tool_run_id)
            if agent_id == "unknown" and "/" in target:
                inferred = self._infer_agent_from_path(target)
                if inferred:
                    agent_id = inferred
            flushed = self._flush_pending_exec()
            flushed.append(ActionEvent(
                ts=ts,
                session_id=self._last_tool_run_id or "unknown",
                agent_id=agent_id,
                action_type=action_type,
                target=target,
                args={"tool": tool_name},
                result_summary=error_msg[:500],
                source="openclaw_log",
            ))
            return flushed

        return []

    @staticmethod
    def _log_entry_to_event(data: dict) -> ActionEvent | None:
        """Convert a log entry dict to an ActionEvent (legacy format support)."""
        ts_str = data.get("timestamp") or data.get("ts")
        if not ts_str:
            return None

        ts = datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        action_map = {
            "tool_error": ActionType.TOOL_CALL,
            "exec_error": ActionType.EXEC,
            "file_error": ActionType.FILE_READ,
            "web_error": ActionType.WEB_FETCH,
        }

        log_type = data.get("type", "tool_call")
        action_type = action_map.get(log_type, ActionType.TOOL_CALL)

        return ActionEvent(
            ts=ts,
            session_id=data.get("session_id", "unknown"),
            agent_id=data.get("agent_id", "unknown"),
            action_type=action_type,
            target=data.get("target", data.get("tool", "")),
            args=data.get("args", {}),
            result_summary=data.get("error", data.get("message", "")),
            bytes_count=data.get("bytes", 0),
            taint_level=TaintLevel.NONE,
            source="openclaw_log",
        )


class FileSystemWatcher:
    """Poll-based file system watcher for agent workspaces."""

    def __init__(self, watch_dirs: list[str] | None = None, poll_interval: float = 2.0) -> None:
        if watch_dirs is None:
            home = Path.home()
            watch_dirs = [str(home / ".openclaw" / "workspace-*")]
        self.watch_patterns = watch_dirs
        self.poll_interval = poll_interval
        self._snapshots: dict[str, tuple[float, int]] = {}  # path -> (mtime, size)

    def _resolve_dirs(self) -> list[Path]:
        """Resolve glob patterns to actual directories."""
        dirs: list[Path] = []
        for pattern in self.watch_patterns:
            parent = Path(pattern).parent
            name_glob = Path(pattern).name
            if parent.exists():
                dirs.extend(d for d in parent.glob(name_glob) if d.is_dir())
        return dirs

    def scan(self, agent_id: str = "workspace") -> list[ActionEvent]:
        """Scan for file changes and return events."""
        events: list[ActionEvent] = []
        now = datetime.now(timezone.utc)

        for watch_dir in self._resolve_dirs():
            try:
                for item in watch_dir.rglob("*"):
                    if not item.is_file():
                        continue
                    # Skip hidden and large files
                    if any(p.startswith(".") for p in item.parts[len(watch_dir.parts):]):
                        continue

                    path_str = str(item)
                    try:
                        stat = item.stat()
                    except OSError:
                        continue

                    current = (stat.st_mtime, stat.st_size)
                    prev = self._snapshots.get(path_str)

                    if prev is None:
                        # New file
                        self._snapshots[path_str] = current
                        events.append(ActionEvent(
                            ts=now,
                            session_id="fs-watcher",
                            agent_id=agent_id,
                            action_type=ActionType.FILE_WRITE,
                            target=path_str,
                            bytes_count=stat.st_size,
                            source="fs_watcher",
                        ))
                    elif current != prev:
                        # Modified file
                        self._snapshots[path_str] = current
                        events.append(ActionEvent(
                            ts=now,
                            session_id="fs-watcher",
                            agent_id=agent_id,
                            action_type=ActionType.FILE_WRITE,
                            target=path_str,
                            bytes_count=stat.st_size,
                            source="fs_watcher",
                        ))

            except PermissionError:
                logger.debug("Permission denied scanning: %s", watch_dir)

        return events

    def initialize_snapshot(self) -> None:
        """Take initial snapshot without generating events."""
        for watch_dir in self._resolve_dirs():
            try:
                for item in watch_dir.rglob("*"):
                    if not item.is_file():
                        continue
                    if any(p.startswith(".") for p in item.parts[len(watch_dir.parts):]):
                        continue
                    try:
                        stat = item.stat()
                        self._snapshots[str(item)] = (stat.st_mtime, stat.st_size)
                    except OSError:
                        continue
            except PermissionError:
                continue

# SimulatedEventGenerator has been moved to watchclaw.simulator.
# This re-export preserves backward compatibility for existing imports.
from watchclaw.simulator import (  # noqa: F401, E402
    SimulatedEventGenerator,
    _AGENT_IDS,
    _BENIGN_AGENTS,
    _ROGUE_AGENT,
)
