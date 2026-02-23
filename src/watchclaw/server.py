"""WatchClaw dashboard API server (stdlib http.server)."""

from __future__ import annotations

import json
import logging
import mimetypes
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Dashboard directory relative to this package
DASHBOARD_DIR = Path(__file__).parent.parent.parent / "dashboard"


def _read_action_log(
    log_path: Path,
    limit: int = 100,
    agent: str | None = None,
    level: str | None = None,
) -> list[dict]:
    """Read and filter action log entries."""
    if not log_path.exists():
        return []
    text = log_path.read_text().strip()
    if not text:
        return []
    entries: list[dict] = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if agent:
            if entry.get("event", {}).get("agent_id") != agent:
                continue
        if level:
            if entry.get("anomaly", {}).get("decision") != level:
                continue
        entries.append(entry)
    return entries[-limit:]


def _build_profiles(log_path: Path) -> list[dict]:
    """Build agent profile summaries from action log."""
    agents: dict[str, dict] = {}
    if not log_path.exists():
        return []
    text = log_path.read_text().strip()
    if not text:
        return []
    for line in text.splitlines():
        try:
            data = json.loads(line)
            aid = data["event"]["agent_id"]
            if aid not in agents:
                agents[aid] = {
                    "agent_id": aid,
                    "count": 0,
                    "normals": 0,
                    "notices": 0,
                    "alerts": 0,
                    "criticals": 0,
                    "action_types": {},
                    "recent_targets": [],
                    "avg_score": 0.0,
                    "max_score": 0.0,
                    "_score_sum": 0.0,
                    "sequences_triggered": [],
                }
            agents[aid]["count"] += 1
            at = data["event"].get("action_type", "unknown")
            agents[aid]["action_types"][at] = agents[aid]["action_types"].get(at, 0) + 1
            dec = data.get("anomaly", {}).get("decision", "")
            if dec == "NORMAL":
                agents[aid]["normals"] += 1
            elif dec == "NOTICE":
                agents[aid]["notices"] += 1
            elif dec == "ALERT":
                agents[aid]["alerts"] += 1
            elif dec == "CRITICAL":
                agents[aid]["criticals"] += 1
            score = data.get("anomaly", {}).get("score", 0)
            agents[aid]["_score_sum"] += score
            if score > agents[aid]["max_score"]:
                agents[aid]["max_score"] = round(score, 3)
            target = data["event"].get("target", "")
            if target:
                agents[aid]["recent_targets"] = (agents[aid]["recent_targets"] + [target])[-5:]
            # Track sequence matches
            seqs = data.get("sequences", [])
            if seqs:
                agents[aid]["sequences_triggered"].extend(seqs)
                agents[aid]["sequences_triggered"] = agents[aid]["sequences_triggered"][-10:]
        except (json.JSONDecodeError, KeyError):
            continue

    # Finalize averages and clean internal fields
    for aid, info in agents.items():
        info["avg_score"] = round(info["_score_sum"] / info["count"], 3) if info["count"] > 0 else 0.0
        del info["_score_sum"]

    return list(agents.values())


def _build_stats(log_path: Path) -> dict[str, Any]:
    """Build summary statistics from action log."""
    if not log_path.exists():
        return {
            "total": 0, "alerts": 0, "criticals": 0, "normals": 0, "notices": 0,
            "alert_rate": 0.0, "top_rules": [], "top_agents": [],
            "decisions": {"NORMAL": 0, "NOTICE": 0, "ALERT": 0, "CRITICAL": 0},
        }

    total = 0
    decisions: dict[str, int] = {"NORMAL": 0, "NOTICE": 0, "ALERT": 0, "CRITICAL": 0}
    rules_count: dict[str, int] = {}
    agents_count: dict[str, int] = {}

    text = log_path.read_text().strip()
    if not text:
        return {
            "total": 0, "alerts": 0, "criticals": 0, "normals": 0, "notices": 0,
            "alert_rate": 0.0, "top_rules": [], "top_agents": [],
            "decisions": {"NORMAL": 0, "NOTICE": 0, "ALERT": 0, "CRITICAL": 0},
        }
    for line in text.splitlines():
        try:
            data = json.loads(line)
            total += 1
            dec = data.get("anomaly", {}).get("decision", "")
            if dec in decisions:
                decisions[dec] += 1
            for r in data.get("rules", []):
                rid = r.get("id", "unknown")
                rules_count[rid] = rules_count.get(rid, 0) + 1
            aid = data.get("event", {}).get("agent_id", "unknown")
            agents_count[aid] = agents_count.get(aid, 0) + 1
        except (json.JSONDecodeError, KeyError):
            continue

    top_rules = sorted(rules_count.items(), key=lambda x: x[1], reverse=True)[:5]
    top_agents = sorted(agents_count.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total": total,
        "normals": decisions["NORMAL"],
        "notices": decisions["NOTICE"],
        "alerts": decisions["ALERT"],
        "criticals": decisions["CRITICAL"],
        "decisions": decisions,
        "alert_rate": (decisions["ALERT"] + decisions["CRITICAL"]) / total if total > 0 else 0.0,
        "top_rules": [{"id": k, "count": v} for k, v in top_rules],
        "top_agents": [{"id": k, "count": v} for k, v in top_agents],
    }


def make_handler(action_log: Path, dashboard_dir: Path) -> type:
    """Create a request handler class bound to specific paths."""

    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # silence default logging

        def _send_json(self, data: Any) -> None:
            body = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8080")
            self.end_headers()
            self.wfile.write(body)

        def _serve_file(self, file_path: Path, content_type: str | None = None) -> None:
            if not file_path.exists():
                self.send_error(404, "Not found")
                return
            if content_type is None:
                content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
            body = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(body)

        def _parse_qs(self) -> dict[str, str]:
            """Parse query string parameters."""
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            return {k: v[0] for k, v in params.items()}

        def _safe_int(self, value: str, default: int) -> int:
            """Parse an integer from a query string value, returning default on failure."""
            try:
                return int(value)
            except (ValueError, TypeError):
                return default

        def do_GET(self) -> None:
            try:
                self._handle_get()
            except Exception:
                logger.exception("Error handling request: %s", self.path)
                self.send_error(500, "Internal server error")

        def _handle_get(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/api/actions":
                qs = self._parse_qs()
                limit = self._safe_int(qs.get("limit", "100"), 100)
                agent = qs.get("agent")
                level = qs.get("level")
                entries = _read_action_log(action_log, limit=limit, agent=agent, level=level)
                self._send_json(entries)

            elif path == "/api/alerts":
                qs = self._parse_qs()
                limit = self._safe_int(qs.get("limit", "50"), 50)
                entries = _read_action_log(action_log, limit=500)
                alerts = []
                for e in entries:
                    if e.get("anomaly", {}).get("decision") in ("ALERT", "CRITICAL"):
                        alert_entry = dict(e)
                        alerts.append(alert_entry)
                self._send_json(alerts[-limit:])

            elif path == "/api/profiles":
                profiles = _build_profiles(action_log)
                self._send_json(profiles)

            elif path == "/api/stats":
                stats = _build_stats(action_log)
                self._send_json(stats)

            elif path == "/" or path == "/index.html":
                self._serve_file(dashboard_dir / "index.html", "text/html")

            elif path.startswith("/dashboard/"):
                rel = path[len("/dashboard/"):]
                file_path = dashboard_dir / rel
                # Prevent directory traversal
                try:
                    file_path.resolve().relative_to(dashboard_dir.resolve())
                except ValueError:
                    self.send_error(403, "Forbidden")
                    return
                self._serve_file(file_path)

            else:
                self.send_error(404)

    return DashboardHandler


def run_server(
    port: int = 8080,
    action_log: str | Path = "/tmp/watchclaw/action.log",
    dashboard_path: str | Path | None = None,
    host: str = "127.0.0.1",
) -> None:
    """Start the dashboard HTTP server.

    Binds to 127.0.0.1 by default to prevent exposure to the public network.
    """
    log_path = Path(action_log)
    dash_dir = Path(dashboard_path) if dashboard_path else DASHBOARD_DIR

    handler = make_handler(log_path, dash_dir)
    server = HTTPServer((host, port), handler)

    print(f"WatchClaw Dashboard: http://{host}:{port}")
    print(f"Action log: {log_path}")
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        print("\nDashboard stopped.")
