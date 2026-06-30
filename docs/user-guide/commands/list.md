---
title: list
---
# `stratus list`

## Sample Usage

```bash title="List all available attack techniques"
stratus list
```

```title="List available attack techniques for AWS"
stratus list --platform aws
```

```title="List available attack techniques for the MITRE ATT&CK 'persistence' tactic"
stratus list --platform aws --mitre-attack-tactic persistence
```

```bash title="Output the list of attack techniques as JSON (for automation/SIEM ingestion)"
stratus list --output json
```

Using `--output json` (or `-o json`) emits one object per technique with its
`id`, `name`, `platform`, `isSlow`, `isIdempotent` and `mitreAttackTactics`. The
`--output` flag is global and also works with `stratus status` and `stratus show`.