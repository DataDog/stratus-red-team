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

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create the IAM user and attach the 'AdministratorAccess' managed IAM policy to it.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.malicious-iam-user
```