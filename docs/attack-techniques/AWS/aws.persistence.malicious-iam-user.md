---
title: Create an administrative IAM User
---

# Create an administrative IAM User 

Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a new IAM user with administrative permissions.

Warm-up: None.

Detonation: Creates the IAM user and attached 'AdministratorAccess' to it.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.malicious-iam-user
```