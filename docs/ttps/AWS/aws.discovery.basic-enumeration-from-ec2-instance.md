# Execute discovery commands on an EC2 instance

Platform: AWS

## MITRE ATT&CK Tactics

- Discovery

## Description


Runs several suspicious discovery commands on an EC2 instance:

- sts:GetCallerIdentity
- s3:ListBuckets
- iam:GetAccountSummary


Warm-up: Create the pre-requisite EC2 instance and VPC (takes a few minutes).

Detonation: Run the commands, over SSM.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.discovery.basic-enumeration-from-ec2-instance
```