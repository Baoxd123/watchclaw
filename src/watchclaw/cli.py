"""WatchClaw CLI: command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

import watchclaw


def _load_config(config_path: str | None) -> dict:
    """Load config from YAML file."""
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    # Try default location
    default = Path(__file__).parent.parent.parent / "configs" / "default-config.yaml"
    if default.exists():
        with open(default) as f:
            return yaml.safe_load(f) or {}
    return {}


def cmd_start(args: argparse.Namespace) -> None:
    """Start the WatchClaw engine."""
    config = _load_config(args.config)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    from watchclaw.engine import WatchClawEngine
    engine = WatchClawEngine(config=config)

    # Load rules
    rules_path = config.get("rules_path")
    if not rules_path:
        default_rules = Path(__file__).parent.parent.parent / "configs" / "default-rules.yaml"
        if default_rules.exists():
            engine.rule_engine.load_rules(default_rules)

    print(f"WatchClaw v{watchclaw.__version__} starting...")
    if args.simulate:
        print("Running in simulation mode")
    try:
        engine.start(simulate=args.simulate)
    except KeyboardInterrupt:
        engine.stop()
        print("\nWatchClaw stopped.")


def cmd_status(args: argparse.Namespace) -> None:
    """Show WatchClaw status."""
    log_path = Path("/tmp/watchclaw/action.log")
    if log_path.exists():
        lines = log_path.read_text().strip().splitlines()
        print(f"WatchClaw v{watchclaw.__version__}")
        print(f"Action log: {log_path} ({len(lines)} entries)")
    else:
        print(f"WatchClaw v{watchclaw.__version__}")
        print("No action log found. Engine may not have been started.")


def cmd_logs(args: argparse.Namespace) -> None:
    """Read/filter action log."""
    log_path = Path("/tmp/watchclaw/action.log")
    if not log_path.exists():
        print("No action log found.")
        return

    lines = log_path.read_text().strip().splitlines()

    # Filter by agent
    if args.agent:
        lines = [
            l for l in lines
            if args.agent in l
        ]

    # Filter by level
    if args.level:
        lines = [
            l for l in lines
            if f'"decision": "{args.level}"' in l
        ]

    # Tail
    tail = args.tail or 20
    lines = lines[-tail:]

    for line in lines:
        try:
            data = json.loads(line)
            event = data.get("event", {})
            anomaly = data.get("anomaly", {})
            print(
                f"{event.get('ts', '?')} "
                f"[{anomaly.get('decision', '?')}] "
                f"{event.get('agent_id', '?')}: "
                f"{event.get('action_type', '?')} -> {event.get('target', '?')[:60]} "
                f"(score={anomaly.get('score', 0):.2f})"
            )
        except json.JSONDecodeError:
            print(line)


def cmd_profile(args: argparse.Namespace) -> None:
    """Show agent profile info."""
    log_path = Path("/tmp/watchclaw/action.log")
    if not log_path.exists():
        print("No action log found.")
        return

    # Aggregate stats from log
    agents: dict[str, dict] = {}
    with log_path.open() as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                agent = data["event"]["agent_id"]
                if agent not in agents:
                    agents[agent] = {"count": 0, "alerts": 0, "escalations": 0}
                agents[agent]["count"] += 1
                decision = data.get("anomaly", {}).get("decision", "")
                if decision == "ALERT":
                    agents[agent]["alerts"] += 1
                elif decision == "CRITICAL":
                    agents[agent]["escalations"] += 1
            except (json.JSONDecodeError, KeyError):
                continue

    if args.agent_id:
        info = agents.get(args.agent_id)
        if info:
            print(f"Agent: {args.agent_id}")
            print(f"  Events: {info['count']}")
            print(f"  Alerts: {info['alerts']}")
            print(f"  Escalations: {info['escalations']}")
        else:
            print(f"No data for agent: {args.agent_id}")
    else:
        print(f"{'Agent':<30} {'Events':>8} {'Alerts':>8} {'Escalations':>12}")
        print("-" * 62)
        for agent_id, info in sorted(agents.items()):
            print(f"{agent_id:<30} {info['count']:>8} {info['alerts']:>8} {info['escalations']:>12}")


def cmd_rules(args: argparse.Namespace) -> None:
    """List rules or test an event against them."""
    from watchclaw.rules import RuleEngine

    engine = RuleEngine()
    rules_path = Path(__file__).parent.parent.parent / "configs" / "default-rules.yaml"
    if rules_path.exists():
        engine.load_rules(rules_path)

    if args.test:
        # Test a single event against rules
        event_path = Path(args.test)
        if not event_path.exists():
            print(f"File not found: {args.test}")
            sys.exit(1)
        with event_path.open() as f:
            data = json.load(f)
        from watchclaw.models import ActionEvent
        event = ActionEvent.from_dict(data)
        matches = engine.evaluate(event)
        if matches:
            for m in matches:
                print(f"  MATCH  [{m.severity}] {m.rule_id}: {m.rule_name}")
                print(f"         {m.description}")
        else:
            print("  No rules matched.")
    else:
        # List all rules
        if not engine.rules:
            print("No rules loaded.")
            return
        print(f"{'ID':<16} {'Severity':<10} {'Action':<8} Name")
        print("-" * 70)
        for rule in engine.rules:
            print(f"{rule.id:<16} {rule.severity:<10} {rule.action:<8} {rule.name}")


def cmd_dashboard(args: argparse.Namespace) -> None:
    """Start the dashboard HTTP server."""
    config = _load_config(getattr(args, "config", None))
    action_log = config.get("action_log", "/tmp/watchclaw/action.log")

    from watchclaw.server import run_server
    run_server(port=args.port, action_log=action_log, host=args.host)


_COLOR_ENABLED: bool | None = None


def _use_color() -> bool:
    """Check if stdout supports ANSI colors (cached)."""
    global _COLOR_ENABLED
    if _COLOR_ENABLED is None:
        _COLOR_ENABLED = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    return _COLOR_ENABLED


# ANSI color codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_CYAN = "\033[36m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_WHITE = "\033[37m"
_BG_RED = "\033[41m"

_DECISION_COLORS = {
    "NORMAL": _GREEN,
    "NOTICE": _YELLOW,
    "ALERT": f"{_YELLOW}{_BOLD}",
    "CRITICAL": f"{_RED}{_BOLD}",
}

_AGENT_COLORS = {
    "melody": _CYAN,
    "judy": _BLUE,
    "teddy": _WHITE,
    "elodie": _GREEN,
    "rogue_agent": _MAGENTA,
}

# Human-readable pattern names for sequence display
_SEQUENCE_LABELS = {
    "read_then_exfil": "Data Exfiltration",
    "config_then_escalate": "Config Tampering",
    "external_trigger_chain": "Cognitive Injection",
}


def _c(color: str, text: str) -> str:
    """Wrap text in color codes if terminal supports it."""
    if not _use_color():
        return text
    return f"{color}{text}{_RESET}"


def _format_sim_line(event, result, seq_matches=None, taint_info=None, rule_matches=None) -> str:
    """Format a single simulation event for terminal output with colors."""
    ts_str = event.ts.strftime("%H:%M:%S")
    agent_raw = event.agent_id[:11]
    agent = agent_raw.ljust(11)
    action = event.action_type.value.ljust(12)
    target = event.target[:42].ljust(42)
    decision_str = result.decision.value
    score = f"{result.score:.2f}"

    # Color the decision
    dec_color = _DECISION_COLORS.get(decision_str, "")
    colored_decision = _c(dec_color, decision_str.ljust(8))

    # Color the agent
    agent_color = _AGENT_COLORS.get(event.agent_id, _WHITE)
    colored_agent = _c(agent_color, agent)

    # Score coloring (dim for low, bold red for high)
    if result.score >= 0.7:
        colored_score = _c(f"{_RED}{_BOLD}", score)
    elif result.score >= 0.5:
        colored_score = _c(f"{_YELLOW}{_BOLD}", score)
    elif result.score >= 0.3:
        colored_score = _c(_YELLOW, score)
    else:
        colored_score = _c(_DIM, score)

    # Dim timestamp
    colored_ts = _c(_DIM, f"[{ts_str}]")

    line = f"{colored_ts} {colored_agent} {action} {target} {colored_decision} {colored_score}"

    # Add rule match details
    if rule_matches:
        for m in rule_matches:
            severity_color = _RED if m.severity in ("critical", "high") else _YELLOW
            line += f"\n{'':>14}{_c(_DIM, chr(0x251c) + chr(0x2500))} {_c(severity_color, 'RULE')}: {m.rule_id} {m.rule_name} [{m.severity}]"

    # Add sequence match details
    if seq_matches:
        for m in seq_matches:
            label = _SEQUENCE_LABELS.get(m.pattern_name, m.pattern_name)
            line += f"\n{'':>14}{_c(_DIM, chr(0x251c) + chr(0x2500))} {_c(f'{_RED}{_BOLD}', 'SEQUENCE')}: {label} (+{m.score_boost:.1f})"
            line += f"\n{'':>14}{_c(_DIM, chr(0x2502))}  {_c(_DIM, m.description)}"

    # Add taint info
    if taint_info:
        for ti in taint_info:
            line += f"\n{'':>14}{_c(_DIM, chr(0x2514) + chr(0x2500))} {_c(_YELLOW, 'TAINT')}: {ti['source']} (sensitivity={ti['sensitivity']:.1f})"

    return line


def _print_summary(counts, seq_summary, rule_summary, agent_counts, engine) -> None:
    """Print a colored summary after simulation completes."""
    total = counts["total"]
    if total == 0:
        return

    bar_width = 20
    sep = _c(_DIM, "=" * 78)

    print(f"\n{sep}")
    print(_c(_BOLD, "  Simulation Summary"))
    print(sep)

    # Decision breakdown with bar chart
    print(f"\n  {_c(_BOLD, 'Decisions')} ({total} events):")
    for dec, color in [("NORMAL", _GREEN), ("NOTICE", _YELLOW), ("ALERT", f"{_YELLOW}{_BOLD}"), ("CRITICAL", f"{_RED}{_BOLD}")]:
        n = counts.get(dec, 0)
        pct = n / total * 100 if total > 0 else 0
        filled = round(pct / 100 * bar_width)
        bar = _c(color, "\u2588" * filled) + _c(_DIM, "\u2591" * (bar_width - filled))
        label = _c(color, f"{dec:<9}")
        print(f"    {label} {n:>3}  {bar}  {pct:4.0f}%")

    # Agent breakdown
    if agent_counts:
        print(f"\n  {_c(_BOLD, 'Agents')}:")
        for agent_id, info in sorted(agent_counts.items()):
            agent_color = _AGENT_COLORS.get(agent_id, _WHITE)
            esc_count = info.get("CRITICAL", 0)
            alert_count = info.get("ALERT", 0)
            total_agent = info.get("total", 0)
            threat = ""
            if esc_count > 0:
                threat = _c(f"{_RED}{_BOLD}", f"  [{esc_count} escalations]")
            elif alert_count > 0:
                threat = _c(f"{_YELLOW}{_BOLD}", f"  [{alert_count} alerts]")
            print(f"    {_c(agent_color, agent_id.ljust(14))} {total_agent:>3} events{threat}")

    # Sequence detections
    if seq_summary:
        print(f"\n  {_c(_BOLD, 'Attack Sequences Detected')}:")
        for pattern, count in sorted(seq_summary.items(), key=lambda x: -x[1]):
            label = _SEQUENCE_LABELS.get(pattern, pattern)
            print(f"    {_c(f'{_RED}{_BOLD}', chr(0x25cf))} {label} {_c(_DIM, f'x{count}')}")

    # Rules triggered
    if rule_summary:
        print(f"\n  {_c(_BOLD, 'Rules Triggered')}:")
        for (rule_id, rule_name), count in sorted(rule_summary.items(), key=lambda x: -x[1]):
            print(f"    {rule_id}: {rule_name} {_c(_DIM, f'(x{count})')}")

    # Log paths
    print(f"\n  {_c(_DIM, 'Logs')}:")
    print(f"    {_c(_DIM, f'action.log:   {engine._action_log_path}')}")
    print(f"    {_c(_DIM, f'sequence.log: {engine._sequence_log_path}')}")
    print(f"    {_c(_DIM, f'audit.log:    {engine._audit_log_path}')}")
    print()


def cmd_simulate(args: argparse.Namespace) -> None:
    """Run simulated events through the engine."""
    config = _load_config(getattr(args, "config", None))

    # Suppress noisy warnings during simulate (Discord webhook, rule match logs)
    logging.basicConfig(
        level=logging.ERROR,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    from watchclaw.engine import WatchClawEngine
    from watchclaw.parser import SimulatedEventGenerator
    from watchclaw.taint import compute_file_sensitivity

    engine = WatchClawEngine(config=config)

    # Load rules
    rules_path = config.get("rules_path")
    if not rules_path:
        default_rules = Path(__file__).parent.parent.parent / "configs" / "default-rules.yaml"
        if default_rules.exists():
            engine.rule_engine.load_rules(default_rules)

    gen = SimulatedEventGenerator(attack_ratio=args.attack_ratio)
    realistic = getattr(args, "realistic", False)

    # Header
    print(_c(_BOLD, f"WatchClaw v{watchclaw.__version__}") + _c(_DIM, " simulate mode"))
    print(f"  Duration: {args.duration}s | Attack ratio: {_c(_YELLOW, f'{args.attack_ratio:.0%}')}")
    if realistic:
        print(f"  Mode: {_c(_CYAN, 'realistic multi-agent')}")
    print()

    counts = {"total": 0, "NORMAL": 0, "NOTICE": 0, "ALERT": 0, "CRITICAL": 0}
    seq_summary: dict[str, int] = {}
    rule_summary: dict[tuple[str, str], int] = {}
    agent_counts: dict[str, dict[str, int]] = {}

    if realistic:
        stream = gen.generate_realistic_stream(duration=args.duration)
    else:
        stream = gen.generate_stream(duration=args.duration, attack_ratio=args.attack_ratio)

    # Collect all events first, then sort by timestamp for chronological display
    events = sorted(stream, key=lambda e: e.ts)

    for event in events:
        result = engine.process_event(event)
        counts["total"] += 1
        counts[result.decision.value] = counts.get(result.decision.value, 0) + 1

        # Track per-agent stats
        aid = event.agent_id
        if aid not in agent_counts:
            agent_counts[aid] = {"total": 0}
        agent_counts[aid]["total"] = agent_counts[aid].get("total", 0) + 1
        agent_counts[aid][result.decision.value] = agent_counts[aid].get(result.decision.value, 0) + 1

        # Capture sequence and rule matches from engine
        seq_matches = engine._last_seq_matches
        rule_matches = engine._last_rule_matches

        # Track summaries
        for m in seq_matches:
            seq_summary[m.pattern_name] = seq_summary.get(m.pattern_name, 0) + 1
        for m in rule_matches:
            key = (m.rule_id, m.rule_name)
            rule_summary[key] = rule_summary.get(key, 0) + 1

        # Compute taint info for display
        taint_info = []
        sensitivity = compute_file_sensitivity(event.target)
        if sensitivity >= 0.5:
            taint_entries = engine.taint_table.get_entries()
            for te in taint_entries:
                if te.source == event.target:
                    taint_info.append({
                        "source": te.source,
                        "sensitivity": sensitivity,
                    })

        print(_format_sim_line(
            event, result,
            seq_matches=seq_matches or None,
            taint_info=taint_info or None,
            rule_matches=rule_matches or None,
        ))

    _print_summary(counts, seq_summary, rule_summary, agent_counts, engine)


def cmd_report(args: argparse.Namespace) -> None:
    """Print a text summary report."""
    log_path = Path("/tmp/watchclaw/action.log")
    if not log_path.exists():
        print("No action log found.")
        return

    # Parse --last duration
    last_str = args.last
    hours = 24.0
    if last_str:
        if last_str.endswith("h"):
            hours = float(last_str[:-1])
        elif last_str.endswith("d"):
            hours = float(last_str[:-1]) * 24
        elif last_str.endswith("m"):
            hours = float(last_str[:-1]) / 60
        else:
            hours = float(last_str)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    total = 0
    alerts = 0
    escalations = 0
    agents: dict[str, int] = {}
    rules_count: dict[str, int] = {}

    with log_path.open() as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                ts_str = data.get("event", {}).get("ts", "")
                if ts_str:
                    ts = datetime.fromisoformat(ts_str)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts < cutoff:
                        continue
                total += 1
                dec = data.get("anomaly", {}).get("decision", "")
                if dec == "ALERT":
                    alerts += 1
                elif dec == "CRITICAL":
                    escalations += 1
                aid = data.get("event", {}).get("agent_id", "unknown")
                agents[aid] = agents.get(aid, 0) + 1
                for r in data.get("rules", []):
                    rid = r.get("id", "unknown")
                    rules_count[rid] = rules_count.get(rid, 0) + 1
            except (json.JSONDecodeError, KeyError):
                continue

    print(f"WatchClaw Report (last {last_str or '24h'})")
    print("=" * 50)
    print(f"Total actions:  {total}")
    print(f"Alerts:         {alerts}")
    print(f"Escalations:    {escalations}")
    rate = (alerts + escalations) / total * 100 if total > 0 else 0
    print(f"Alert rate:     {rate:.1f}%")

    if agents:
        print(f"\nTop Agents:")
        for aid, cnt in sorted(agents.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {aid:<30} {cnt} events")

    if rules_count:
        print(f"\nTop Rules Triggered:")
        for rid, cnt in sorted(rules_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {rid:<20} {cnt} hits")


def cmd_serve(args: argparse.Namespace) -> None:
    """Start the dashboard HTTP server (legacy alias for dashboard)."""
    cmd_dashboard(args)


def cmd_version(args: argparse.Namespace) -> None:
    """Show version."""
    print(f"watchclaw {watchclaw.__version__}")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="watchclaw",
        description="WatchClaw — AI Agent Runtime Security Monitor",
        epilog="Documentation: docs/architecture.md, docs/signals.md, docs/rules.md",
    )
    subparsers = parser.add_subparsers(dest="command")

    # start
    p_start = subparsers.add_parser("start", help="Start monitoring OpenClaw agents")
    p_start.add_argument("--config", metavar="FILE", help="Path to config YAML")
    p_start.add_argument("--simulate", action="store_true", help="Generate simulated events instead of reading logs")
    p_start.set_defaults(func=cmd_start)

    # simulate
    p_simulate = subparsers.add_parser("simulate", help="Run attack simulation for testing")
    p_simulate.add_argument("--duration", type=float, default=60, metavar="SEC", help="Simulation duration in seconds (default: 60)")
    p_simulate.add_argument("--attack-ratio", type=float, default=0.1, metavar="RATIO", help="Fraction of malicious events, 0.0-1.0 (default: 0.1)")
    p_simulate.add_argument("--realistic", action="store_true", help="Multi-agent scenario with melody/judy/rogue_agent")
    p_simulate.add_argument("--config", metavar="FILE", help="Path to config YAML")
    p_simulate.set_defaults(func=cmd_simulate)

    # dashboard
    p_dashboard = subparsers.add_parser("dashboard", help="Launch web dashboard")
    p_dashboard.add_argument("--port", type=int, default=8080, metavar="PORT", help="Listen port (default: 8080)")
    p_dashboard.add_argument("--host", default="127.0.0.1", metavar="HOST", help="Bind address (default: 127.0.0.1)")
    p_dashboard.add_argument("--config", metavar="FILE", help="Path to config YAML")
    p_dashboard.set_defaults(func=cmd_dashboard)

    # report
    p_report = subparsers.add_parser("report", help="Print security report")
    p_report.add_argument("--last", default="24h", metavar="DURATION", help="Time window: 24h, 1d, 30m (default: 24h)")
    p_report.set_defaults(func=cmd_report)

    # logs
    p_logs = subparsers.add_parser("logs", help="View and filter action logs")
    p_logs.add_argument("--tail", type=int, default=20, metavar="N", help="Number of recent entries (default: 20)")
    p_logs.add_argument("--agent", metavar="ID", help="Filter by agent ID")
    p_logs.add_argument("--level", metavar="LEVEL", help="Filter by decision: NORMAL, NOTICE, ALERT, CRITICAL")
    p_logs.set_defaults(func=cmd_logs)

    # profile
    p_profile = subparsers.add_parser("profile", help="Show agent behavioral profiles")
    p_profile.add_argument("agent_id", nargs="?", metavar="AGENT_ID", help="Show details for a specific agent")
    p_profile.set_defaults(func=cmd_profile)

    # rules
    p_rules = subparsers.add_parser("rules", help="List security rules or test events")
    p_rules.add_argument("--test", metavar="EVENT.json", help="Test a JSON event file against all rules")
    p_rules.set_defaults(func=cmd_rules)

    # status
    p_status = subparsers.add_parser("status", help="Show engine status")
    p_status.set_defaults(func=cmd_status)

    # serve (legacy alias)
    p_serve = subparsers.add_parser("serve", help="Start dashboard server (alias for 'dashboard')")
    p_serve.add_argument("--port", type=int, default=8080, metavar="PORT", help="Listen port (default: 8080)")
    p_serve.add_argument("--host", default="127.0.0.1", metavar="HOST", help="Bind address (default: 127.0.0.1)")
    p_serve.add_argument("--config", metavar="FILE", help="Path to config YAML")
    p_serve.set_defaults(func=cmd_serve)

    # version
    p_version = subparsers.add_parser("version", help="Show version")
    p_version.set_defaults(func=cmd_version)

    parsed = parser.parse_args(argv)
    if hasattr(parsed, "func"):
        parsed.func(parsed)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
