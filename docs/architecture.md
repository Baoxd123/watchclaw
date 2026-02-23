# WatchClaw Architecture

WatchClaw is a three-layer detection engine that runs as an independent process alongside AI agents. It ingests agent actions, scores them against behavioral baselines and hard rules, and escalates high-confidence anomalies to an LLM auditor for semantic analysis.

## Design Principles

1. **Independence**: WatchClaw runs as a separate process. The monitored agent's LLM cannot influence its judgment. Even a fully hijacked agent cannot disable monitoring.

2. **Layered detection**: Three layers from fast/deterministic to slow/semantic. 99% of normal actions pass through Layer 1 in microseconds. Only ~1% reach the LLM auditor.

3. **Observe, don't block (MVP)**: Like Zeek for network traffic, WatchClaw records, analyzes, and alerts — but doesn't intercept. This minimizes false positive impact and makes adoption easy.

4. **Continuous learning**: Per-agent profiles adapt through observation and user feedback. The system gets more accurate over time without manual tuning.

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                   Event Sources                          │
│                                                         │
│  OpenClaw Gateway Logs    Filesystem Watcher             │
│  (/tmp/openclaw/*.log)    (~/.openclaw/workspace-*)      │
│                                                         │
│  Simulated Events (for testing/demo)                     │
└──────────────────────┬──────────────────────────────────┘
                       │ ActionEvent
          ┌────────────▼────────────┐
          │   WatchClaw Engine      │
          │   (engine.py)           │
          │   Orchestration hub     │
          └────────────┬────────────┘
                       │
      ┌────────────────┼────────────────┐
      │                │                │
┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼──────┐
│  Layer 1  │   │  Taint    │   │ Sequence   │
│  Rules    │   │  Tracker  │   │ Detector   │
│ (rules.py)│   │(taint.py) │   │(sequence.py│
└─────┬─────┘   └─────┬─────┘   └─────┬──────┘
      └────────────────┼────────────────┘
                       │
          ┌────────────▼────────────┐
          │  Layer 2: Scorer        │
          │  (scorer.py)            │
          │  6 signals → score      │
          │  → NORMAL/LOG/ALERT/ESC  │
          └────────────┬────────────┘
                       │ if CRITICAL
          ┌────────────▼────────────┐
          │  Layer 3: LLM Auditor   │
          │  (auditor.py)           │
          │  Semantic verdict       │
          └────────────┬────────────┘
                       │
      ┌────────────────┼────────────────┐
      │                │                │
┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼──────┐
│ action.log│   │  Discord  │   │ Dashboard  │
│ (JSONL)   │   │  Alerts   │   │ (HTTP API) │
└───────────┘   └───────────┘   └────────────┘
```

## Layer 1: Hard Rules

**File**: `rules.py` | **Config**: `configs/default-rules.yaml`
**Speed**: microseconds | **Decision**: BLOCK or ALERT

Hard rules are deterministic, YAML-defined checks for known-bad patterns. They fire before any scoring happens.

### Rule Structure

```yaml
- id: WC-HARD-001
  name: Block watchclaw modification
  severity: critical
  action: block
  conditions:
    action_type: [file_write]
    target_pattern: "watchclaw"
```

### Condition Types

| Condition | Description | Example |
|-----------|-------------|---------|
| `action_type` | Match specific action types | `[file_read, file_write]` |
| `target_pattern` | Regex on file path or URL | `"\\.ssh/(id_rsa\|id_ed25519)"` |
| `command_pattern` | Regex on executed command | `"base64.*\\|.*sh"` |
| `content_match` | Regex on event content | `"ignore previous instructions"` |
| `count_within` | Rate limiting (N events in T seconds) | `{count: 3, seconds: 60}` |
| `sequence` | Ordered action chain within time window | See `default-rules.yaml` |

### 15 Built-in Rules

Rules cover self-protection (WC-HARD-001), cognitive file writes (002), obfuscated execution (003), bulk credential access (004), prompt injection (005), data exfiltration sequences (006), memory poisoning (007), SSH key access (008), config tampering (009), direct IP requests (010), DNS exfiltration (011), reverse shells (012), package installation (013), scheduled tasks (014), and large file uploads (015).

## Layer 2: Behavior Engine

**Files**: `scorer.py`, `taint.py`, `sequence.py`, `models.py`
**Speed**: milliseconds | **Decision**: NORMAL / LOG / ALERT / CRITICAL

Layer 2 combines three components:

### Anomaly Scorer (scorer.py)

Computes a weighted score from 6 independent signals (see [signals.md](signals.md) for details). Each signal returns a value between 0.0 and 1.0. The weighted average determines the decision:

| Score | Decision | Action |
|-------|----------|--------|
| < 0.3 | NORMAL | No action |
| 0.3 - 0.5 | LOG | Record in action.log |
| 0.5 - 0.7 | ALERT | Send Discord notification |
| >= 0.7 | CRITICAL | Forward to Layer 3 LLM Auditor |

Signal weights are per-agent and adapt through user feedback (marking alerts as true/false positives).

### Taint Tracker (taint.py)

Tracks data sensitivity as it flows through agent actions. When an agent reads a sensitive file (e.g., `.env`, sensitivity=0.9), a taint entry is created. The taint score decays exponentially:

```
score = sensitivity × exp(-0.693 × elapsed_seconds / half_life)
```

Default half-life: 300 seconds (5 minutes).

- At t=0: full sensitivity (0.9)
- At t=5min: half (0.45)
- At t=10min: quarter (0.225)
- At t=20min: negligible (0.056)

**User intent sanitization**: If the user says "send my config to X," all active taints are marked sanitized and no longer contribute to the anomaly score. The action is still logged for audit.

### Sequence Detector (sequence.py)

Maintains a global sliding window of 50 recent actions and matches against known multi-step attack patterns (pattern matching filters by agent):

| Pattern | Steps | Window | Score Boost |
|---------|-------|--------|-------------|
| `read_then_exfil` | Sensitive file read → web_fetch/exec | 120s | +0.40 |
| `config_then_escalate` | Config write → privileged exec | 60s | +0.50 |
| `external_trigger_chain` | Web fetch → cognitive file write | 30s | +0.60 |

## Layer 3: LLM Auditor

**File**: `auditor.py`, `features.py`
**Speed**: seconds | **Trigger**: Only when Layer 2 score >= 0.7

The LLM Auditor provides semantic intent analysis for escalated events. It receives structured metadata and content features — never raw file contents — to prevent prompt injection against the auditor itself.

### Content Feature Extraction (features.py)

Instead of raw content, the auditor receives deterministic features extracted by regex/entropy:

- Shannon entropy (high = possible encryption/encoding)
- API key pattern counts (sk-, AKIA, ghp_, etc.)
- Email/IP/URL pattern counts
- Private key markers
- File type and structure hints

### Security Design

1. **No raw content**: Auditor never sees file contents or HTTP bodies
2. **Independent instance**: Separate API key and context from the monitored agent
3. **Fixed system prompt**: Hardcoded in WatchClaw, cannot be influenced externally
4. **Output-only**: Auditor returns a structured verdict (SAFE/SUSPICIOUS/MALICIOUS), cannot execute tools

### Cost

~5 LLM calls per day per active agent. At Haiku pricing: < $1/year.

## Event Ingestion

**File**: `parser.py`

### OpenClaw Log Parser

Reads JSONL logs from the OpenClaw gateway (`/tmp/openclaw/`). Extracts tool calls, maps tool names to action types, and maintains session-to-agent correlation. Tail-friendly (tracks file positions, reads only new entries).

### Simulated Event Generator

Generates synthetic events for testing and demos. Supports configurable attack ratios and a realistic multi-agent mode with distinct agent personas (melody=developer, judy=assistant, rogue_agent=attacker).

## Data Model

**File**: `models.py`

### Core Types

- **ActionEvent**: Single agent action (timestamp, agent_id, action_type, target, args)
- **ActionType**: file_read, file_write, exec, web_fetch, message_send, tool_call
- **AgentProfile**: Learned behavioral model (hourly activity, common files/domains, tool call rate stats, signal weights, maturity score)
- **AnomalyResult**: Scoring output (score, 6 signals, decision)
- **AuditVerdict**: LLM judgment (verdict, confidence, reason)

### Agent Profile Learning

Profiles use Welford's online algorithm for running statistics (mean/stddev without storing history). Maturity tracks from 0.0 (new) to 1.0 (fully learned, ~100 observations). New agents blend with a conservative default profile during cold-start.

## Output

### Logs

| Log | Format | Content |
|-----|--------|---------|
| `action.log` | JSONL | Every action with event, anomaly score, signals, rules, sequences |
| `sequence.log` | JSONL | Detected sequence pattern matches |
| `audit.log` | JSONL | LLM auditor verdicts for escalated events |

### Alerts

Discord webhook with rich embeds. Color-coded by severity (orange=ALERT, red=CRITICAL). Shows top 3 contributing signals and auditor verdict if available.

### Dashboard

Single-file web UI (`dashboard/index.html`). Real-time action timeline, alert list, agent profile cards, and summary statistics. Served via built-in HTTP server with polling-based updates.

## File Map

| File | Lines | Purpose |
|------|-------|---------|
| `cli.py` | ~610 | CLI commands and simulation formatting |
| `parser.py` | ~900 | Event ingestion and simulation generation |
| `engine.py` | ~315 | Orchestration and layer coordination |
| `scorer.py` | ~220 | 6-signal anomaly computation |
| `models.py` | ~280 | Data classes and running statistics |
| `rules.py` | ~160 | YAML rule engine |
| `sequence.py` | ~157 | Pattern detection |
| `taint.py` | ~161 | Exponential decay model |
| `features.py` | ~120 | Content feature extraction |
| `auditor.py` | ~47 | LLM interface (MVP stub) |
| `alerter.py` | ~115 | Discord webhook |
| `server.py` | ~279 | HTTP API and dashboard serving |
