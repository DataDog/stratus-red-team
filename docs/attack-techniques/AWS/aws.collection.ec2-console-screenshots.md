---
title: Retrieve EC2 Console Screenshots
---

# Retrieve EC2 Console Screenshots 

Platform: AWS

## MITRE ATT&CK Tactics


- Collection

## Description


Runs ec2:GetConsoleScreenshot from a role that does not have permission to do so. This simulates an attacker attempting to
retrieve screenshots of multiple running EC2 instances, to identify potentially juicy data and/or targets.

See https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetConsoleScreenshot.html

Warm-up: Create an IAM role without permissions to run ec2:GetConsoleScreenshot.

Detonation: Assume the role and run a number of ec2:GetConsoleScreenshot calls (which will be denied) on fictitious EC2 instance identifiers.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.collection.ec2-console-screenshots
```