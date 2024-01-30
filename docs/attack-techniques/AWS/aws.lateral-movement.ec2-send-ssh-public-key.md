---
title: Usage of ec2instanceconnect:SendSSHPublicKey on multiple instances
---

# Usage of ec2instanceconnect:SendSSHPublicKey on multiple instances

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Lateral Movement

## Description


Simulates an attacker pushing a Secure Shell (SSH) public key to multiple EC2 instances, which then will allow anyone with the corresponding private key to 
connect directly to the systems via SSH.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create multiple EC2s instances and VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>: 

- Adds a public SSH key to the EC2 for 60 seconds.

References:

- https://sysdig.com/blog/2023-global-cloud-threat-report/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.lateral-movement.ec2-send-ssh-public-key
```
## Detection


Identify, through CloudTrail's <code>SendSSHPublicKey</code> event, when a user is adding an SSH key to multiple EC2s.


