---
title: Backdoor an IAM Role
---

# Backdoor an IAM Role 

Platform: AWS

## MITRE ATT&CK Tactics


- Persistence

## Description


Establishes persistence by backdooring an existing IAM role, allowing it to be assumed from an external AWS account.

Warm-up: Creates the pre-requisite IAM role.

Detonation: Updates the assume role policy of the IAM role to backdoor it.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.backdoor-iam-role
```