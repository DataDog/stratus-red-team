# Create an administrative IAM user

Platform: AWS

## MITRE ATT&CK Tactics

- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a new IAM user with administrative permissions.

Warm-up: None.

Detonation: Creates the IAM user and attached 'AdministratorAccess' to it.


## Instructions

```bash title="Detonate me!"
stratus detonate aws.persistence.malicious-iam-user
```