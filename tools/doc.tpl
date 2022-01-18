# {{.FriendlyName}}

Platform: {{.Platform}}

## MITRE ATT&CK Tactics

{{JoinTactics .MitreAttackTactics}}

## Description

{{.Description}}

## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate {{.ID}}
```