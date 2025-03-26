---
title: Delete Bedrock Guardrail
---

# Delete Bedrock Guardrail




Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Delete an Amazon Bedrock guardrail. Simulates an attacker disrupting AI safety controls.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Bedrock guardrail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Delete the Bedrock guardrail.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.bedrock-guardrail-delete
```
## Detection


Identify when a Bedrock guardrail is deleted, through CloudTrail's <code>DeleteModelGuardrail</code> event.


