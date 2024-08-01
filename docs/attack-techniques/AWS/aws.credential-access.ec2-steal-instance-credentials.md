---
title: Steal EC2 Instance Credentials
---

# Steal EC2 Instance Credentials

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Simulates the theft of EC2 instance credentials from the Instance Metadata Service.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create the prerequisite EC2 instance and VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>:

- Execute a SSM command on the instance to retrieve temporary credentials
- Use these credentials locally (outside the instance) to run the following commands:
	- sts:GetCallerIdentity
	- ec2:DescribeInstances


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.ec2-steal-instance-credentials
```
## Detection


GuardDuty provides two findings to identify stolen EC2 instance credentials.

- [InstanceCredentialExfiltration.OutsideAWS](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialexfiltrationoutsideaws) identifies EC2 instance credentials used from outside an AWS account.
- [InstanceCredentialExfiltration.InsideAWS
](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialexfiltrationinsideaws) identifies EC2 instance credentials used from a different AWS account than the one of the EC2 instance.

See also: [Known detection bypasses](https://hackingthe.cloud/aws/avoiding-detection/steal-keys-undetected/).




