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
## Detection


Using CloudTrail's <code>DeleteFlowLogs</code> event.

To reduce the risk of false positives related to VPC deletion in development environments, alerts can be raised
only when <code>DeleteFlowLogs</code> is not closely followed by <code>DeleteVpc</code>.


