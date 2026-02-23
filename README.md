# WatchClaw

> **Runtime security monitor for AI Agents** — Zeek for the AI Agent era.

AI Agents can read files, execute commands, and make network requests autonomously. When an agent is hijacked via prompt injection, it looks like normal operation — Suricata and EDR can't see the difference. WatchClaw monitors agent behavior at the semantic level: it learns baselines, tracks data sensitivity, and detects attack patterns like read-then-exfiltrate chains that network-layer tools miss entirely.

## The Problem

AI agents like OpenClaw have full system access: file I/O, shell commands, HTTP requests. A prompt injection attack can silently redirect this power.

**Real attack scenario** (CVE-2026-25253, CVSS 8.8): A malicious webpage injects instructions into an agent's context. The agent reads `~/.ssh/id_rsa` and `~/.env`, then `curl`s the contents to an attacker-controlled domain. The entire chain looks like normal tool usage — no malware binary, no exploit payload, no anomalous network signature.

Traditional security tools fail here:

- **Suricata/Zeek** see a normal HTTPS POST — nothing to flag
- **EDR** sees a legitimate process reading a file — nothing unusual
- **SecureClaw** runs inside the agent's own LLM — a hijacked agent ignores its own constraints

The attack is invisible at every layer except one: **the semantic sequence of agent actions**.

## How WatchClaw Works

```
                 ┌─────────────────────────────┐
                 │     Event Ingestion          │
                 │  OpenClaw logs / filesystem  │
                 └─────────────┬───────────────┘
                               │
                 ┌─────────────▼───────────────┐
                 │  Layer 1: Hard Rules (YAML)  │  ← microseconds
                 │  15 deterministic rules      │
                 └─────────────┬───────────────┘
                               │
                 ┌─────────────▼───────────────┐
                 │  Layer 2: Behavior Engine    │  ← milliseconds
                 │  6-signal anomaly scoring    │
                 │  + taint tracking + sequences│
                 └─────────────┬───────────────┘
                               │ score ≥ 0.7
                 ┌─────────────▼───────────────┐
                 │  Layer 3: LLM Auditor        │  ← seconds
                 │  Semantic intent analysis    │
                 └─────────────┬───────────────┘
                               │
                 ┌─────────────▼───────────────┐
                 │  Output: action.log │ alerts │
                 │  Discord │ dashboard         │
                 └─────────────────────────────┘
```

**Layer 1** catches known-bad patterns instantly — obfuscated commands, credential file sweeps, reverse shells. **Layer 2** scores every action against learned per-agent behavioral baselines using 6 weighted signals, taint tracking with exponential decay, and sequence pattern detection. **Layer 3** sends only high-score events (~1% of traffic) to an independent LLM for semantic judgment.

## Demo

<p align="center">
  <img src="docs/demo.svg" alt="WatchClaw simulate — detecting data exfiltration and cognitive injection">
</p>

Normal agents (melody, teddy, judy, elodie) perform routine operations — git, pytest, file writes. The **rogue_agent** reads `credentials.json` and `id_ed25519`, tainting those reads. When it later requests `evil-exfil.com/upload`, WatchClaw detects the **read-then-exfiltrate sequence** and marks it as CRITICAL. It also catches the agent writing to `SOUL.md` after fetching external instructions — a **cognitive injection** attack.

```bash
pip install -e .
watchclaw simulate --duration 25 --attack-ratio 0.2
```

## Quick Start

```bash
# Install
pip install -e .

# Monitor real OpenClaw agents
watchclaw start

# Run attack simulation for testing
watchclaw simulate --duration 60 --attack-ratio 0.1

# Open web dashboard
watchclaw dashboard --port 8080

# Print security report
watchclaw report --last 24h
```

## Key Features

### Behavioral Baselines
WatchClaw learns each agent's normal patterns — when they're active, which files they touch, which domains they request, how fast they work. A dev agent reading source files at 2pm is normal. The same agent reading `.env` at 3am after 4 hours of user silence scores very differently.

### 6-Signal Anomaly Scoring
Every action is scored against 6 independent signals: time anomaly, user idle time, rate bursts, resource sensitivity, destination novelty, and taint flow. Weights adapt per-agent through user feedback — mark a false positive and the contributing signals are automatically dampened.

### Taint Tracking with Decay
When an agent reads `.env`, that data is "tainted." The taint decays exponentially (5-minute half-life) — a `curl` 30 seconds later is highly suspicious, but the same `curl` 20 minutes later barely registers. If the user explicitly says "send my config to X," the taint is sanitized. The action is still logged for audit, but no alert fires.

### Sequence Pattern Detection
Single actions are ambiguous. Sequences tell the story. WatchClaw detects multi-step attack chains:
- **read_then_exfil**: Read `.env` → `curl` to unknown domain (within 120s)
- **config_then_escalate**: Write config → run privileged command (within 60s)
- **external_trigger_chain**: Fetch external URL → write to `SOUL.md` (within 30s)

### 15 Hard Rules (YAML)
Zero-tolerance rules for known-bad patterns: reverse shells, obfuscated execution (`base64 -d | sh`), bulk credential sweeps, cognitive file tampering, SSH key access. Rules are extensible via `configs/default-rules.yaml`.

### Independent Observer
WatchClaw runs as a separate process. The monitored agent's LLM cannot influence WatchClaw's judgment — even a fully hijacked agent cannot disable or bypass monitoring. This is the fundamental advantage over in-agent approaches like SecureClaw.

## vs Existing Tools

| Capability | WatchClaw | SecureClaw | agentsh | Suricata/Zeek | EDR |
|---|---|---|---|---|---|
| Independent of agent process | **Yes** | No (runs inside agent) | Yes | Yes | Yes |
| Behavioral baseline learning | **Yes** | No | No | No | No |
| Sequence pattern detection | **Yes** | No | No | Partial | No |
| Taint tracking with decay | **Yes** | No | No | No | No |
| Adaptive per-agent weights | **Yes** | No | No | No | No |
| Semantic-level visibility | **Yes** | Partial | No | No | No |
| Resistant to prompt injection | **Yes** | No (can be jailbroken) | Yes | N/A | N/A |
| LLM-powered audit layer | **Yes** | No | No | No | No |

**agentsh** tells you "the agent ran `curl`." WatchClaw tells you "the agent read `.env` at 3am, then `curl`ed a domain registered yesterday, while the user has been idle for 4 hours — this is likely data exfiltration."

## Configuration

Default config: `configs/default-config.yaml`

```yaml
log_dir: /tmp/openclaw              # OpenClaw log directory
action_log: /tmp/watchclaw/action.log
watch_dirs:
  - ~/.openclaw/workspace-*         # Directories to monitor
poll_interval: 2.0                  # Seconds between log checks
taint_half_life: 300.0              # 5-minute decay (per-agent tunable)
discord_webhook_url: null           # Set for real-time alerts

thresholds:
  normal: 0.3                        # < 0.3 = normal
  log: 0.5                          # 0.3-0.5 = logged, no alert
  alert: 0.7                        # 0.5-0.7 = alert sent
                                    # ≥ 0.7 = critical, triggers LLM auditor
auditor:
  enabled: false
  api_key: null
```

Security rules: `configs/default-rules.yaml` (15 rules, fully customizable)

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Event Sources                             │
│  OpenClaw Logs  │  File System Watcher  │  Simulated Events      │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                ┌────────────▼────────────┐
                │   WatchClaw Engine      │
                │   (Orchestration Hub)   │
                └────────────┬────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
  ┌──────▼──────┐    ┌──────▼──────┐    ┌───────▼──────┐
  │  Layer 1    │    │  Taint      │    │  Sequence    │
  │  Hard Rules │    │  Tracker    │    │  Detector    │
  │  (YAML)     │    │  (Decay)    │    │  (Patterns)  │
  └──────┬──────┘    └──────┬──────┘    └───────┬──────┘
         └───────────────────┼───────────────────┘
                             │
                ┌────────────▼────────────┐
                │  Layer 2: Anomaly       │
                │  Scorer (6 Signals)     │
                │  Adaptive Weights       │
                └────────────┬────────────┘
                             │
                ┌────────────▼────────────┐
                │  Layer 3: LLM Auditor   │
                │  (if score ≥ 0.7)       │
                └────────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │ Discord Alerts  │          │  Action Log     │
     │ (Webhook)       │          │  (JSONL Audit)  │
     └─────────────────┘          └─────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for detailed layer specifications.

## CLI Reference

```
watchclaw start [--config FILE] [--simulate]   Start monitoring
watchclaw simulate [--duration N] [--attack-ratio N] [--realistic]
watchclaw dashboard [--port N]                 Launch web dashboard
watchclaw report [--last 24h|1d|30m]           Print security report
watchclaw logs [--tail N] [--agent ID] [--level ALERT]
watchclaw profile [AGENT_ID]                   Show agent profiles
watchclaw rules [--test EVENT.json]            List or test rules
watchclaw status                               Show engine status
watchclaw version                              Show version
```

## Documentation

- [Design Document](docs/design.md) — Problem statement, architecture rationale, and technical design
- [Architecture](docs/architecture.md) — Three-layer detection engine deep dive
- [Anomaly Signals](docs/signals.md) — The 6 signals and how scoring works
- [Writing Rules](docs/rules.md) — Custom rule authoring guide

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Acknowledgments

Built for the [OpenClaw](https://github.com/openclaw/openclaw) ecosystem. Inspired by [Zeek](https://zeek.org)'s philosophy of comprehensive network monitoring applied to the AI agent layer.
