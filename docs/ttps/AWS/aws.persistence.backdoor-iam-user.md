# Create an access key on an existing IAM user

Platform: AWS

## MITRE ATT&CK Tactics

- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating an access key on an existing IAM user.

Warm-up: Create the pre-requisite IAM user.

Detonation: Create the access key.


## Instructions

```bash title="Detonate me!"
stratus detonate aws.persistence.backdoor-iam-user
```