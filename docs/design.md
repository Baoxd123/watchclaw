# WatchClaw Design Document

**Version**: 0.2  
**Date**: 2026-02-20  
**Author**: Eric Bao  
**License**: MIT  
**Repository**: [github.com/Baoxd123/watchclaw](https://github.com/Baoxd123/watchclaw)

---

## 1. Problem Statement

### 1.1 The Security Gap

AI agent systems like OpenClaw are entering production environments with capabilities that traditional software lacks:

- **Autonomous decision-making**: Agents independently decide what to do next
- **Tool invocation**: Agents read/write files, execute shell commands, and make HTTP requests
- **Persistent memory**: Agents retain context across sessions — memory itself can be poisoned
- **Natural language control**: Agent behavior is driven by prompts, which are injectable

MITRE ATLAS identified **7 novel attack techniques** specific to AI agent systems and documented **4 real-world case studies**, including memory poisoning, skill supply chain attacks, and cognitive file tampering. CVE-2026-25253 (CVSS 8.8) demonstrated a 1-click RCE attack chain through prompt injection.

### 1.2 Why Existing Tools Fail

| Tool | Layer | Core Limitation |
|------|-------|----------------|
| **Suricata/Zeek** | Network IDS | Agent attacks occur at the application/semantic layer; network tools see only encrypted HTTPS POSTs |
| **SecureClaw** | In-agent LLM constraints | Rules are prompts — a hijacked agent can bypass its own constraints |
| **agentsh** | Syscall interception | Hard rules only, no behavioral baselines or semantic understanding; Linux only |
| **Agent-SPM** | Embedded SDK | Runs inside the agent process, not independent monitoring |
| **EDR** | Process/file monitoring | Sees legitimate file reads and API calls, cannot judge semantic intent |

The fundamental problem:

> "The malicious behavior is hidden in the semantic intent of the agent's actions, not in the technical execution."

Traditional security tools answer "what did the agent do?" but agent security requires understanding "why is the agent doing this?"

### 1.3 WatchClaw's Position

```
Suricata/Zeek  = behavioral analysis engine for network traffic
WatchClaw      = behavioral analysis engine for agent actions
```

WatchClaw is a **security monitor that runs independently from the agent**, analyzing action sequences with contextual signals and optional LLM-based semantic judgment to detect hijacked or anomalous agent behavior.

Like Zeek, WatchClaw does not block — it logs, analyzes, and alerts. This "monitor-first" approach:

- Produces forensic-grade audit trails answering "when did the compromise start, what data was accessed?"
- Enables delayed but still useful alerting (attack chains take seconds to minutes; 2-second alert latency allows manual intervention)
- Builds behavioral baselines over time, forming the foundation for future enforcement
- Satisfies compliance/audit requirements ("prove the agent didn't exfiltrate data")

---

## 2. Architecture

### 2.1 System Overview

```
┌──────────────────────────────────────────────────────────┐
│                   AI Agent (OpenClaw)                      │
│  User Message → LLM Reasoning → Action Execution          │
└──────────────────────────┬───────────────────────────────┘
                           │ Action Events (JSONL logs)
                           ▼
┌──────────────────────────────────────────────────────────┐
│                  WatchClaw (independent process)           │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │              Event Ingestion                        │  │
│  │  Parse OpenClaw logs → standardized WatchClaw events│  │
│  └───────────────────────┬────────────────────────────┘  │
│                          │                               │
│            ┌─────────────▼──────────────┐                │
│            │   Layer 1: Hard Rules      │  ← µs          │
│            │   Deterministic matching   │                │
│            │   15 YAML-defined rules    │                │
│            └─────────────┬──────────────┘                │
│                          │ PASS                          │
│            ┌─────────────▼──────────────┐                │
│            │   Layer 2: Behavior Engine │  ← ms          │
│            │   6-signal anomaly scoring │                │
│            │   Taint tracking + decay   │                │
│            │   Sequence detection       │                │
│            └─────────────┬──────────────┘                │
│                          │ score ≥ threshold             │
│            ┌─────────────▼──────────────┐                │
│            │   Layer 3: LLM Auditor     │  ← seconds     │
│            │   Independent semantic     │                │
│            │   intent analysis          │                │
│            └─────────────┬──────────────┘                │
│                          │                               │
│            ┌─────────────▼──────────────┐                │
│            │   Output                   │                │
│            │   action.log / alerts /    │                │
│            │   dashboard / Discord      │                │
│            └────────────────────────────┘                │
└──────────────────────────────────────────────────────────┘
```

### 2.2 Design Principles

1. **Independence**: WatchClaw runs as a separate process. A compromised agent cannot influence or disable monitoring.
2. **Layered cost**: Cheap deterministic checks first; expensive LLM judgment only for the ~1% of events that warrant it.
3. **Monitor, don't block**: Log everything, alert on anomalies. Blocking deferred to a future version pending agent platform hook APIs.
4. **Per-agent adaptation**: Each agent develops its own behavioral profile. What's normal for a dev assistant is suspicious for a life assistant.

---

## 3. Detection Engine

### 3.1 Layer 1: Hard Rules

YAML-defined deterministic rules that match against action type, target path, and command patterns. Zero-tolerance rules for known-bad patterns.

**Examples**:
- `WC-HARD-001`: Reverse shell detection (`/dev/tcp`, `nc -e`, `bash -i`)
- `WC-HARD-002`: Cognitive file writes (SOUL.md, MEMORY.md, AGENTS.md)
- `WC-HARD-003`: Obfuscated execution (`base64 -d | sh`, `eval $(`)
- `WC-HARD-008`: SSH private key access
- `WC-HARD-012`: Reverse shell via common utilities

Rules support:
- Regex pattern matching on target and args
- Action type filtering
- Severity levels (low/medium/high/critical)
- Taint source conditions (e.g., only trigger if data has external taint)

Full rule reference: [docs/rules.md](rules.md)

### 3.2 Layer 2: Behavioral Anomaly Scoring

Every action is scored against **6 independent signals**, each producing a value in [0, 1]:

| Signal | What it measures | Example |
|--------|-----------------|---------|
| **time_anomaly** | Action outside agent's normal active hours | Dev agent working at 3 AM |
| **user_idle** | Duration since last user interaction | Agent acting after 4 hours of silence |
| **rate_burst** | Action rate vs historical baseline (z-score) | Sudden spike in file reads |
| **resource_anomaly** | Target sensitivity + novelty | Reading `.env` vs `README.md` |
| **destination_anomaly** | Domain/IP novelty and reputation | Request to newly-registered `.tk` domain |
| **taint_flow** | Tainted data flowing to outbound action | Reading `.env` then `curl`ing to external URL |

**Composite score**: Weighted sum of signals, normalized to [0, 1]. Weights are **per-agent and adaptive** — user feedback (true positive / false positive) adjusts signal weights through an exponential moving average.

**Cold-start blending**: New agents use global default weights, linearly blending toward their personal weights as the profile matures (measured by event count).

Full signal documentation: [docs/signals.md](signals.md)

### 3.3 Taint Tracking

When an agent reads sensitive data, that data is "tainted." Taint decays exponentially:

```
taint(t) = sensitivity × e^(-0.693 × elapsed / half_life)
```

- Default half-life: 300 seconds (per-agent configurable)
- A `curl` 30 seconds after reading `.env` is highly suspicious
- The same `curl` 20 minutes later barely registers
- Explicit user intent ("send my config to X") sanitizes active taint entries

Taint sources:
- File reads: sensitivity based on file type (`.env` = 0.9, `.ssh/id_rsa` = 0.95, `README.md` = 0.05)
- External content: `web_fetch` responses create medium-level taint (sensitivity = 0.5)

### 3.4 Sequence Pattern Detection

Individual actions are often ambiguous. Multi-step sequences reveal attack intent:

| Pattern | Steps | Max Gap | Score Boost |
|---------|-------|---------|-------------|
| **read_then_exfil** | Read sensitive file → outbound request | 120s | +0.4 |
| **config_then_escalate** | Write config → privileged command | 60s | +0.5 |
| **external_trigger_chain** | Fetch external URL → write cognitive file | 30s | +0.6 |

When a sequence completes within its time window, the score boost is added to the final anomaly score, potentially escalating the decision from NORMAL to ALERT or CRITICAL.

### 3.5 Layer 3: LLM Auditor

Events scoring above the escalation threshold (~1% of traffic) are sent to an independent LLM for semantic judgment.

**What the auditor receives** (structured metadata only, never raw content):
```json
{
  "agent_id": "melody",
  "action": {"type": "exec", "target": "curl https://example.com/..."},
  "anomaly": {"score": 0.85, "signals": [{"name": "taint_flow", "value": 0.9}]},
  "content_features": {"entropy": 4.2, "api_key_patterns": 2, "url_patterns": 3},
  "context": {"hour": 3, "is_sensitive_target": true}
}
```

**Security design**:
- Raw content is never sent to the auditor LLM, preventing prompt injection against the auditor itself
- Content features (entropy, API key pattern count, PII counts) are extracted by deterministic code
- System prompt is hardcoded and not modifiable by agents
- Output is constrained to `{"verdict": "SAFE|SUSPICIOUS|MALICIOUS", "confidence": 0.0-1.0, "reason": "..."}`

**Fallback**: When no API key is configured, the auditor falls back to a score-based deterministic heuristic (>0.8 = MALICIOUS, >0.6 = SUSPICIOUS, else SAFE).

---

## 4. Log Format

WatchClaw produces four JSONL log files:

| Log | Purpose | Content |
|-----|---------|---------|
| `action.log` | Primary audit trail | Every processed event with decision, score, signals, rule matches |
| `sequence.log` | Attack chain detection | Completed sequence patterns with involved actions and gaps |
| `audit.log` | LLM audit verdicts | Layer 3 judgments with confidence, reason, and latency |
| `cognitive.log` | Identity file changes | Modifications to SOUL.md, MEMORY.md, AGENTS.md |

All logs use JSONL format with ISO 8601 timestamps, suitable for ingestion by SIEM systems or analysis tools.

---

## 5. Integration

### 5.1 Current: Log Tail Mode

WatchClaw monitors OpenClaw gateway JSONL logs and filesystem events:
- Parses `_meta.date` timestamps and `sessionKey` → agent correlation
- Maps 14 OpenClaw tool types to standardized action types
- Watches workspace directories for file system changes

### 5.2 Future: Hook Mode

When the agent platform provides runtime hook APIs, WatchClaw can receive events in real-time with full action context (parameters, content), enabling:
- Real-time blocking (BLOCK decisions enforced before action executes)
- Richer taint tracking with actual content analysis
- Lower latency alerting

---

## 6. Comparison with Existing Tools

| Capability | WatchClaw | SecureClaw | agentsh | Suricata/Zeek | EDR |
|---|---|---|---|---|---|
| Independent of agent | **Yes** | No | Yes | Yes | Yes |
| Behavioral baselines | **Yes** | No | No | No | No |
| Sequence detection | **Yes** | No | No | Partial | No |
| Taint tracking | **Yes** | No | No | No | No |
| Adaptive per-agent weights | **Yes** | No | No | No | No |
| Semantic-level visibility | **Yes** | Partial | No | No | No |
| Resistant to prompt injection | **Yes** | No | Yes | N/A | N/A |
| LLM audit layer | **Yes** | No | No | No | No |

---

## 7. Known Limitations

1. **Log-only mode**: WatchClaw cannot block actions in v0.1; it monitors and alerts only.
2. **Gateway log coverage**: OpenClaw gateway logs currently record errors/warnings but not all successful tool calls. WatchClaw supplements with filesystem monitoring.
3. **LLM Auditor is optional**: Without an API key, Layer 3 uses deterministic fallback. The core value is in Layer 1 + Layer 2 deterministic analysis.
4. **Agent attribution**: ~23% of events from error logs lack session context, resulting in "unknown" agent attribution.
5. **No cross-agent correlation**: Each agent is profiled independently; coordinated multi-agent attacks are not yet detected.
6. **Profile persistence**: Agent profiles are not persisted across restarts in v0.1.

---

## 8. Performance

Target: Layer 1 + Layer 2 combined latency < 5ms per event.

Measured: **0.04ms per event** (~23,500 events/sec) on Apple Silicon, exceeding the target by 125×. Layer 3 LLM calls add ~500ms-2s but are triggered for <1% of events.

---

## 9. Roadmap

### v0.1 (Current)
- Three-layer detection engine (rules + scoring + LLM audit)
- Taint tracking with exponential decay
- Sequence pattern detection
- Per-agent behavioral baselines with adaptive weights
- CLI, dashboard, Discord alerts
- 307 tests, 15 built-in rules

### v0.2 (Planned)
- Profile persistence across restarts
- User feedback integration (Discord reaction → weight adjustment)
- Additional sequence patterns from real attack data
- Cross-agent correlation

### v1.0 (Future)
- Real-time hook mode (requires agent platform API)
- Inline blocking with configurable enforcement policies
- Community-contributed rule library
- Multi-platform support (beyond OpenClaw)

---

## References

- MITRE ATLAS: AI Threat Landscape for Autonomous AI Agent Systems (2026)
- CVE-2026-25253: OpenClaw Gateway URL Parameter Injection (CVSS 8.8)
- Adversa AI: SecureClaw — Security Hardening for AI Agents (2026)
- Zeek Network Security Monitor: [zeek.org](https://zeek.org)
