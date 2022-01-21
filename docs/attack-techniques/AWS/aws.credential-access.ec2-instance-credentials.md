---
title: Steal EC2 Instance Credentials
---

# Steal EC2 Instance Credentials  <span class="w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Simulates the theft of EC2 instance credentials from the Instance Metadata Service.

Warm-up:Create the pre-requisite EC2 instance and VPC (takes a few minutes).

Detonation:

- Execute a SSM command on the instance to retrieve temporary credentials
- Use these credentials locally (outside the instance) using a few standard discovery commands.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.ec2-instance-credentials
```