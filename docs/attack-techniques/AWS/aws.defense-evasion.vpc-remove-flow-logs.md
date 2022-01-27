---
title: Remove VPC Flow Logs
---

# Remove VPC Flow Logs




Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Removes a VPC Flog Logs configuration from a VPC.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a VPC with a VPC Flow Logs configuration.

<span style="font-variant: small-caps;">Detonation</span>: 

- Remove the VPC Flow Logs configuration.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.vpc-remove-flow-logs
```