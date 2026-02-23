# Writing Custom Rules

WatchClaw's Layer 1 uses YAML-defined hard rules for deterministic, microsecond-level pattern matching. Rules fire before behavioral scoring and handle known-bad patterns that should never occur.

## Rule File Location

Default rules: `configs/default-rules.yaml`

To use a custom rules file, set `rules_path` in your config:

```yaml
# configs/my-config.yaml
rules_path: /path/to/my-rules.yaml
```

Or keep the default rules and add your own to the same file.

## Rule Structure

```yaml
rules:
  - id: WC-CUSTOM-001
    name: Human-readable name
    description: What this rule detects and why
    severity: critical | high | medium
    action: block | alert
    conditions:
      action_type: [file_read, file_write, exec, web_fetch, message_send, tool_call]
      target_pattern: "regex pattern"
      command_pattern: "regex pattern"
      content_match: "regex pattern"
    count_within:
      count: 3
      seconds: 60
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (e.g., `WC-CUSTOM-001`) |
| `name` | Yes | Short name shown in alerts |
| `description` | No | Detailed explanation |
| `severity` | Yes | `critical`, `high`, or `medium` |
| `action` | Yes | `block` (prevent action) or `alert` (notify only) |
| `conditions` | Yes | Matching criteria (see below) |
| `count_within` | No | Rate limiting: trigger only after N matches in T seconds |

## Condition Types

### action_type

Match specific action types. Can be a single string or a list:

```yaml
# Single type
conditions:
  action_type: file_read

# Multiple types
conditions:
  action_type:
    - file_read
    - file_write
```

Available types: `file_read`, `file_write`, `exec`, `web_fetch`, `message_send`, `tool_call`

### target_pattern

Regex matched against the action's target (file path or URL):

```yaml
# Match .env files anywhere
conditions:
  target_pattern: "\\.env$"

# Match files in a specific directory
conditions:
  target_pattern: "/secrets/.*"

# Match multiple patterns
conditions:
  target_pattern: "\\.(env|key|pem|credentials)$"
```

### command_pattern

Regex matched against executed commands (only applies to `exec` actions):

```yaml
# Detect base64 decoding piped to shell
conditions:
  action_type: exec
  command_pattern: "base64\\s+-d.*\\|"

# Detect privilege escalation
conditions:
  action_type: exec
  command_pattern: "sudo\\s+"
```

### content_match

Regex matched against event content or tool output:

```yaml
# Detect prompt injection attempts
conditions:
  content_match: "ignore\\s+(previous|all)\\s+instructions"
```

### count_within

Trigger only when the rule matches N times within T seconds for the same agent:

```yaml
# Alert on 3+ credential file reads within 1 minute
- id: WC-CUSTOM-002
  name: Rapid credential sweep
  severity: high
  action: alert
  conditions:
    action_type: file_read
    target_pattern: "\\.(env|key|pem)$"
  count_within:
    count: 3
    seconds: 60
```

## Examples

### Block SSH Key Access

```yaml
- id: WC-CUSTOM-010
  name: SSH key access
  description: Prevent agents from reading SSH private keys
  severity: critical
  action: block
  conditions:
    action_type:
      - file_read
    target_pattern: "\\.ssh/(id_rsa|id_ed25519|id_ecdsa)$"
```

### Alert on Cryptocurrency Wallet Access

```yaml
- id: WC-CUSTOM-011
  name: Crypto wallet access
  description: Alert when agents access cryptocurrency wallet files
  severity: high
  action: alert
  conditions:
    action_type:
      - file_read
      - file_write
    target_pattern: "(wallet\\.dat|\\.bitcoin/|metamask|keystore/UTC)"
```

### Block Mass File Deletion

```yaml
- id: WC-CUSTOM-012
  name: Mass file deletion
  description: Block commands that delete multiple files
  severity: critical
  action: block
  conditions:
    action_type: exec
    command_pattern: "(rm\\s+-rf|find.*-delete|shred\\s+)"
```

### Alert on Cloud Credential Access

```yaml
- id: WC-CUSTOM-013
  name: Cloud credential access
  description: Alert on access to cloud provider credentials
  severity: high
  action: alert
  conditions:
    action_type: file_read
    target_pattern: "(\\.aws/credentials|\\.gcloud/|azure.*\\.json|kube/config)"
```

### Rate-Limited Database Dump Detection

```yaml
- id: WC-CUSTOM-014
  name: Rapid database operations
  description: Alert on suspicious burst of database-related commands
  severity: high
  action: alert
  conditions:
    action_type: exec
    command_pattern: "(mysqldump|pg_dump|mongodump|sqlite3.*\\.dump)"
  count_within:
    count: 2
    seconds: 30
```

## Testing Rules

Test a single event against all loaded rules:

```bash
# Create a test event
cat > /tmp/test-event.json << 'EOF'
{
  "ts": "2026-01-15T14:00:00Z",
  "session_id": "test",
  "agent_id": "melody",
  "action_type": "file_read",
  "target": "/home/user/.ssh/id_rsa",
  "args": {}
}
EOF

# Test against rules
watchclaw rules --test /tmp/test-event.json
```

Output:
```
  MATCH  [critical] WC-HARD-008: SSH private key access
         Block agents from reading SSH private keys
```

## Listing Rules

View all loaded rules:

```bash
watchclaw rules
```

Output:
```
ID               Severity   Action   Name
----------------------------------------------------------------------
WC-HARD-001      critical   block    Block watchclaw modification
WC-HARD-002      high       alert    Cognitive file write
WC-HARD-003      high       alert    Obfuscated command
...
```

## Built-in Rules Reference

| ID | Name | Severity | Action | What It Catches |
|----|------|----------|--------|-----------------|
| WC-HARD-001 | Block watchclaw modification | critical | block | Agents tampering with WatchClaw files |
| WC-HARD-002 | Cognitive file write | high | alert | Writes to SOUL.md, IDENTITY.md, etc. |
| WC-HARD-003 | Obfuscated command | high | alert | base64 decode, eval, curl-pipe-sh |
| WC-HARD-004 | Bulk credential access | high | alert | 3+ credential files in 60 seconds |
| WC-HARD-005 | Prompt injection pattern | high | alert | "ignore previous instructions" etc. |
| WC-HARD-006 | Read then network request | critical | alert | Credential read → HTTP request chain |
| WC-HARD-007 | Memory file modification | high | alert | External-triggered MEMORY.md writes |
| WC-HARD-008 | SSH private key access | critical | block | Reading id_rsa, id_ed25519, etc. |
| WC-HARD-009 | OpenClaw config modification | critical | block | Tampering with gateway config |
| WC-HARD-010 | Direct IP network request | high | alert | HTTP to raw IP (bypassing DNS) |
| WC-HARD-011 | DNS exfiltration | high | alert | dig/nslookup data exfiltration |
| WC-HARD-012 | Reverse shell attempt | critical | block | nc -e, /dev/tcp, bash -i |
| WC-HARD-013 | Package installation | medium | alert | pip/npm/yarn install commands |
| WC-HARD-014 | Scheduled task creation | high | alert | crontab, at, schtasks |
| WC-HARD-015 | Large file upload | high | alert | curl -F, wget --upload |

## Tips

- Use `critical` severity for actions that should never happen (SSH key access, reverse shells)
- Use `high` for actions that might be legitimate but need review (cognitive file writes)
- Use `medium` for informational alerts (package installation)
- Prefer `alert` over `block` during initial deployment to understand your agents' behavior before enforcing
- Use `count_within` to reduce noise from rules that match common individual operations but are suspicious in bulk
- Test your rules with `watchclaw rules --test` before deploying
