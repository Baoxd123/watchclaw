# Changelog

All notable changes to WatchClaw will be documented in this file.

## [0.1.0] - 2026-02-22

### Added
- **Three-layer detection engine**
  - Layer 1: YAML-based hard rule matching (15 built-in rules)
  - Layer 2: 6-signal behavioral anomaly scoring with per-agent adaptive weights
  - Layer 3: LLM auditor via Anthropic API with deterministic fallback
- **Taint tracking** with exponential decay (configurable half-life per agent)
- **Sequence pattern detection** for multi-step attack chains (read_then_exfil, config_then_escalate, external_trigger_chain)
- **Per-agent behavioral baselines** with cold-start blending and maturity tracking
- **Content feature extraction** (Shannon entropy, API key patterns, PII detection)
- **OpenClaw log parser** supporting gateway JSONL logs and filesystem monitoring
- **CLI commands**: `start`, `simulate`, `dashboard`, `report`, `logs`, `profile`, `rules`, `status`, `version`
- **Web dashboard** with real-time event display (localhost-only)
- **Discord webhook alerting** with color-coded severity embeds
- **JSONL audit logging**: action.log, sequence.log, audit.log
- **Simulation mode** with multi-agent scenarios and configurable attack ratios
- **307 tests** covering all modules
- **Documentation**: architecture, signals reference, rule authoring guide, design document
