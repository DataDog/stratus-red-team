# {{.FriendlyName}}

Platform: {{.Platform}}

## MITRE ATT&CK Tactics

{{JoinTactics .MitreAttackTactics}}

## Description

{{.Description}}

## Instructions

```bash title="Detonate me!"
stratus detonate {{.ID}}
```