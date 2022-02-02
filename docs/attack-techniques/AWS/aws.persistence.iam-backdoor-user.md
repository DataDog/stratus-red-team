---
title: Create an Access Key on an IAM User
---

# Create an Access Key on an IAM User




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating an access key on an existing IAM user.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an IAM user.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create an IAM access key on the user.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-backdoor-user
```
## Detection


Through CloudTrail's <code>CreateAccessKey</code> event. This event can hardly be considered suspicious by itself, unless
correlated with other indicators.
'

