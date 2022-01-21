---
title: Attempt to Leave the AWS Organization
---

# Attempt to Leave the AWS Organization 

Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Attempts to leave the AWS Organization (unsuccessfully - will hit an AccessDenied error).

Warm-up: Create an IAM role without permissions to run organizations:LeaveOrganization

Detonation: Calls organization:LeaveOrganization to simulate an attempt to leave the AWS Organization.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.leave-organization
```