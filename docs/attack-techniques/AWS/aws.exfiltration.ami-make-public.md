# Exfiltrate an AMI by Making it Public

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates an AMI by sharing it publicly.

Warm-up: Create an AMI.

Detonation: Share the AMI publicly.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.ami-make-public
```