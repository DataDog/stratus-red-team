# Create a login profile on an IAM user

Platform: AWS

## MITRE ATT&CK Tactics

- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a login profile on an existing IAM user. This allows an attacker to access an IAM
user intended to be used programmatically through the AWS console usual login process. 

Warm-up: Create the pre-requisite IAM user.

Detonation: Create the login profile.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-user-create-login-profile
```