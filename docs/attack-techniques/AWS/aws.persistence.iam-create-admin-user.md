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
stratus detonate aws.persistence.iam-create-admin-user
```
## Detection


Through CloudTrail's <code>CreateUser</code>, <code>AttachUserPolicy</code> and <code>CreateAccessKey</code> events.

While matching on these events may be impractical and prone to false positives in most environments, the following
can help to craft more precise detections:

- Identify a call to <code>CreateUser</code> closely followed by <code>AttachUserPolicy</code> with an administrator policy.

- Identify a call to <code>CreateUser</code> resulting in an access denied error.


