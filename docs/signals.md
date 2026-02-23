# Anomaly Signals

WatchClaw scores every agent action against 6 independent signals. Each signal captures a different dimension of "suspicious" — time, user presence, action rate, resource sensitivity, destination novelty, and data flow. The weighted combination produces a single anomaly score between 0.0 and 1.0.

## How Scoring Works

```
score = Σ(signal_value × signal_weight) / Σ(signal_weight)
```

Each signal returns a value in [0.0, 1.0]. Weights are per-agent and default to:

| Signal | Default Weight | What It Measures |
|--------|---------------|------------------|
| time_anomaly | 0.20 | Activity at unusual hours |
| user_idle | 0.20 | Agent acting without user presence |
| rate_burst | 0.15 | Sudden spike in action frequency |
| resource_anomaly | 0.15 | Access to sensitive or unfamiliar files |
| destination_anomaly | 0.15 | Requests to unknown external domains |
| taint_flow | 0.15 | Propagation of sensitive data |

### Decision Thresholds

| Score Range | Decision | Action |
|-------------|----------|--------|
| < 0.3 | NORMAL | Normal operation, no action |
| 0.3 - 0.5 | LOG | Recorded in action.log, no alert |
| 0.5 - 0.7 | ALERT | Discord notification sent |
| >= 0.7 | CRITICAL | Forwarded to Layer 3 LLM Auditor |

## Signal 1: time_anomaly

**Weight**: 0.20 | **Source**: AgentProfile.hourly_activity

Measures whether the current hour is unusual for this agent. WatchClaw learns each agent's activity distribution over time.

**Computation**:
```
time_anomaly = 1.0 - learned_hour_probability
```

**Examples**:
- Agent normally active 9am-6pm → action at 2pm scores 0.0-0.2
- Same agent at 3am → scores 0.8-1.0

**Cold-start**: New agents (maturity < 1.0) get dampened time anomaly scores (scaled by `min(1.0, 0.3 + 3.5 × maturity)`) to avoid false positives during the learning period. The steep ramp means dampening lifts quickly — by maturity=0.2 (~20 observations), the signal is at full strength.

## Signal 2: user_idle

**Weight**: 0.20 | **Source**: Last user message timestamp

Measures how long since the user last interacted. An agent acting autonomously for hours without user input is more suspicious than one responding to a recent message.

**Computation**:
```
user_idle = min(1.0, idle_seconds / 14400)
```

**Examples**:
- User just sent a message → 0.0
- User idle 30 minutes → 0.125
- User idle 2 hours → 0.5
- User idle 4+ hours → 1.0
- No user message recorded → 0.2 (default)

**Why it matters**: Most prompt injection attacks happen when the user isn't watching. An agent reading `.env` right after the user asked about environment setup is normal. The same read at 3am with no user activity is suspicious.

## Signal 3: rate_burst

**Weight**: 0.15 | **Source**: AgentProfile.tool_call_rate (RunningStats)

Detects sudden spikes in action frequency. Uses z-score against the agent's learned mean/stddev of tool call rate.

**Computation**:
```
z_score = (current_rate - mean) / stddev
rate_burst = min(1.0, max(0.0, (z_score - 2.0) / 3.0))
```

Only z-scores above 2.0 produce a non-zero signal — mild spikes are ignored.

**Examples**:
- Normal rate (within 2σ) → 0.0
- 3σ spike → 0.33
- 4σ spike → 0.67
- 5σ spike → 1.0

**Why it matters**: Exfiltration attacks often involve rapid sequential reads. A normal dev agent might touch 5 files per minute; an attacker sweeping credentials hits 20+ per minute.

## Signal 4: resource_anomaly

**Weight**: 0.15 | **Source**: File sensitivity + agent familiarity

Uses additive scoring: unknown files and sensitive files each contribute independently. Only applies to `file_read` and `file_write` actions.

**Computation**:
```
resource_anomaly = 0.0
if file is unknown (not in common_files):  +0.4
if file is sensitive (sensitivity >= 0.5): +0.6
clamped to [0.0, 1.0]
```

**File Sensitivity Scale**:

| File Pattern | Sensitivity |
|-------------|-------------|
| `.env`, `id_rsa`, `credentials.json` (known sensitive names) | 0.95 |
| `.key`, `.pem`, `.p12`, `.pfx` | 0.95 |
| `.env` (by extension), `.credentials`, `.secret`, `.token` | 0.90 |
| `.crt`, `.cer` | 0.70 |
| `.json`, `.yaml`, `.yml` | 0.40 |
| `.py`, `.js`, `.ts` | 0.30 |
| `.log` | 0.30 |
| `.txt` | 0.20 |
| `.md` | 0.10 |

**Examples**:
- Agent reads `src/main.py` (known file, sensitivity=0.3) → 0.0 (known + not sensitive)
- Agent reads `.env` for the first time (sensitivity=0.95) → 0.4 + 0.6 = 1.0
- Agent reads `.env` (familiar file, sensitivity=0.95) → 0.0 + 0.6 = 0.6

## Signal 5: destination_anomaly

**Weight**: 0.15 | **Source**: AgentProfile.common_domains

Flags outbound requests using a 3-tier threat intelligence model.

**Computation**:
```
if domain in known_bad_domains:       1.0
elif domain in common_domains:        0.1
else:                                 0.4  (unknown)
  + 0.5 if suspicious TLD (.tk, .xyz, etc.)
clamped to [0.0, 1.0]
```

Known-bad domains include: `evil-exfil.com`, `pastebin.com`, `transfer.sh`, `ngrok.io`, `requestbin.net`, `hookbin.com`, `burpcollaborator.net`.

Suspicious TLDs (abuse-heavy free registrars): `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.click`, `.icu`, etc.

**Examples**:
- `curl https://docs.python.org` (known) → 0.1
- `curl https://unknown-site.com` (first seen) → 0.4
- `curl https://data-drop.tk` (unknown + suspicious TLD) → 0.9
- `curl https://pastebin.com` (known bad) → 1.0

## Signal 6: taint_flow

**Weight**: 0.15 | **Source**: TaintTable.aggregate_taint()

Measures how much sensitive data is "in flight" — data that was recently read from sensitive sources and hasn't decayed or been sanitized.

**Computation**:
```
taint_flow = max(sensitivity × exp(-0.693 × elapsed / half_life))
             across all active taint entries
```

**Decay Timeline** (for `.env` read, sensitivity=0.9, half_life=300s):

| Time Since Read | Taint Score |
|----------------|-------------|
| 0s (just read) | 0.90 |
| 60s | 0.77 |
| 300s (5 min) | 0.45 |
| 600s (10 min) | 0.225 |
| 1200s (20 min) | 0.056 |

**User intent sanitization**: When a user message contains transfer-related keywords ("send," "upload," "share," etc.), all active taints are marked sanitized and return 0.0. The original data flow is still logged for audit purposes.

## Adaptive Weights

Signal weights are not static. They adapt per-agent through user feedback:

### False Positive Feedback
When a user marks an alert as false positive, the signals that contributed high values have their weights reduced by 10%:
```
weight *= 0.90  (minimum floor: 0.10)
```

### True Positive Feedback
When confirmed, contributing signals are boosted by 10%:
```
weight *= 1.10  (maximum cap: 2.0)
```

This means a security researcher's agent (who frequently reads `.env` legitimately) will naturally develop lower `resource_anomaly` weight, while a writing assistant's agent will keep high sensitivity to credential access.

## Cold-Start Handling

New agents (maturity < 1.0, fewer than ~100 observations) use blended scoring:

1. Signal weights blend between global defaults and the agent's emerging personal weights
2. Time anomaly is dampened (multiplied by `min(1.0, 0.3 + 3.5 × maturity)`, reaching full strength at maturity=0.2)
3. Resource and destination signals use conservative defaults

Maturity increases from 0.0 to 1.0 as the agent accumulates observations. After ~100 actions, the profile is considered mature and personal weights take full effect.

## Score Boosting from Sequences

When the sequence detector identifies a multi-step pattern (see [architecture.md](architecture.md)), the anomaly score is boosted:

| Pattern | Boost |
|---------|-------|
| read_then_exfil | +0.40 |
| config_then_escalate | +0.50 |
| external_trigger_chain | +0.60 |

This can push a borderline LOG event (score 0.4) into ALERT territory (0.7+), reflecting the much higher risk of coordinated multi-step behavior.
