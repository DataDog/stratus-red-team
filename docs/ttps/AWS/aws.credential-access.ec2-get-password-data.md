# Retrieve EC2 password data

Platform: AWS

## MITRE ATT&CK Tactics

- Credential Access

## Description


Runs ec2:GetPasswordData from a role that does not have permission to do so. This simulates an attacker attempting to
retrieve RDP passwords of Windows EC2 instances.

Warm-up: Create an IAM role without permissions to run ec2:GetPasswordData

Detonation: Assume the role and run a number of ec2:GetPasswordData calls (which will be denied


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.ec2-get-password-data
```