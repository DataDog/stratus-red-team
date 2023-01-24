---
title: Launch Unusual EC2 instances
---

# Launch Unusual EC2 instances


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Execution

## Description


Attempts to launch several unusual EC2 instances (p2.xlarge).

<span style="font-variant: small-caps;">Warm-up</span>: Creates an IAM role that doesn't have permissions to launch EC2 instances. 
This ensures the attempts is not successful, and the attack technique is fast to detonate.

<span style="font-variant: small-caps;">Detonation</span>: Attempts to launch several unusual EC2 instances. The calls will fail as the IAM role does not have sufficient permissions.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.execution.ec2-launch-unusual-instances
```
## Detection


Trough CloudTrail events with the event name <code>RunInstances</code> and error
<code>Client.UnauthorizedOperation</code>. The <code>eventSource</code> will be
<code>ec2.amazonaws.com</code> and the <code>requestParameters.instanceType</code>
field will contain the instance type that was attempted to be launched.

Depending on your account limits you might also see <code>VcpuLimitExceeded</code> error codes.


