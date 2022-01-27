---
title: Execute Discovery Commands on an EC2 Instance
---

# Execute Discovery Commands on an EC2 Instance

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Discovery

## Description


Runs several discovery commands on an EC2 instance:

- sts:GetCallerIdentity
- s3:ListBuckets
- iam:GetAccountSummary
- iam:ListRoles
- iam:ListUsers
- iam:GetAccountAuthorizationDetails
- ec2:DescribeSnapshots
- cloudtrail:DescribeTrails
- guardduty:ListDetectors

The commands will be run under the identity of the EC2 instance role, simulating an attacker having compromised an EC2 instance and running discovery commands on it.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create the prerequisite EC2 instance and VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>: 

- Run the discovery commands, over SSM. The commands will be run under the identity of the EC2 instance role.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.discovery.ec2-enumerate-from-instance
```