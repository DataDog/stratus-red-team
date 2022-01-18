# Remove VPC flow logs

Platform: AWS

## MITRE ATT&CK Tactics

- Defense Evasion

## Description


Removes a VPC Flog Logs configuration from a VPC.

Warm-up: Creates a VPC with a VPC Flow Logs configuration.

Detonation: Removes the VPC Flow Logs configuration.


## Instructions

```bash title="Detonate me!"
stratus detonate aws.defense-evasion.remove-vpc-flow-logs
```