---
title: Download EC2 Instance User Data
---

# Download EC2 Instance User Data


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Discovery

## Description


Runs ec2:DescribeInstanceAttribute on several instances. This simulates an attacker attempting to
retrieve Instance User Data that may include installation scripts and hard-coded secrets for deployment.

See: 

- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- https://hackingthe.cloud/aws/general-knowledge/introduction_user_data/
- https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/ec2__download_userdata/main.py

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an IAM role without permissions to run ec2:DescribeInstanceAttribute

<span style="font-variant: small-caps;">Detonation</span>: 

- Run ec2:DescribeInstanceAttribute on multiple fictitious instance IDs
- These calls will result in access denied errors


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.discovery.ec2-download-user-data
```
## Detection


Through CloudTrail's <code>DescribeInstanceAttribute</code> event.

See:

* [Associated Sigma rule](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_ec2_download_userdata.yml)

