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

Warm-up: Create the pre-requisite IAM user.

Detonation: Create the access key.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.backdoor-iam-user
```