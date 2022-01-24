---
title: Create a Login Profile on an IAM User
---

# Create a Login Profile on an IAM User 

Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a Login Profile on an existing IAM user. This allows an attacker to access an IAM
user intended to be used programmatically through the AWS console usual login process. 

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM user

<span style="font-variant: small-caps;">Detonation</span>: 

- Create an IAM Login Profile on the user


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-user-create-login-profile
```