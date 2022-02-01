---
title: Execute Commands on EC2 Instance via User Data
---

# Execute Commands on EC2 Instance via User Data

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Execution
- Privilege Escalation

## Description


Executes code on a Linux EC2 instance through User Data.

References:

- https://hackingthe.cloud/aws/exploitation/local-priv-esc-mod-instance-att/
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html

<span style="font-variant: small-caps;">Warm-up</span>:

- Create the prerequisite EC2 instance and VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>:

- Stop the instance
- Use ModifyInstanceAttribute to inject a malicious script in user data
- Start the instance
- Upon starting, the malicious script in user data is automatically executed as the root user


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.execution.ec2-user-data
```