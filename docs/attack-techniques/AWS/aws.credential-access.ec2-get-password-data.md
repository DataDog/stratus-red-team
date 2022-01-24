---
title: Retrieve EC2 Password Data
---

# Retrieve EC2 Password Data


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Runs ec2:GetPasswordData from a role that does not have permission to do so. This simulates an attacker attempting to
retrieve RDP passwords on a high number of Windows EC2 instances.

See https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetPasswordData.html

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an IAM role without permissions to run ec2:GetPasswordData

<span style="font-variant: small-caps;">Detonation</span>: 

- Assume the role 
- Run a number of ec2:GetPasswordData calls (which will be denied) using fictious instance IDs


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.ec2-get-password-data
```