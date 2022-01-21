---
title: Execute Discovery Commands on an EC2 Instance
---

# Execute Discovery Commands on an EC2 Instance  <span class="w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Discovery

## Description


Runs several suspicious discovery commands on an EC2 instance:

- sts:GetCallerIdentity
- s3:ListBuckets
- iam:GetAccountSummary
- iam:ListRoles
- iam:ListUsers
- iam:GetAccountAuthorizationDetails
- ec2:DescribeSnapshots
- cloudtrail:DescribeTrails
- guardduty:ListDetectors

Warm-up: Create the pre-requisite EC2 instance and VPC (takes a few minutes).

Detonation: Run the commands, over SSM.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.discovery.basic-enumeration-from-ec2-instance
```