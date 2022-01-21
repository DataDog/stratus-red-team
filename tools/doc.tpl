---
title: {{.FriendlyName}}
---

# {{.FriendlyName}} {{ if .IsSlow }} <span class="w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> {{ end }}

Platform: {{.Platform}}

## MITRE ATT&CK Tactics

{{JoinTactics .MitreAttackTactics "\n- " "\n- "}}

## Description

{{.Description}}

## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate {{.ID}}
```