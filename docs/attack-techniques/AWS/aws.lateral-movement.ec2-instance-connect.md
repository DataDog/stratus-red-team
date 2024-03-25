---
title: Usage of EC2 Instance Connect on multiple instances
---

# Usage of EC2 Instance Connect on multiple instances

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Lateral Movement

## Description


Simulates an attacker pushing an SSH public key to multiple EC2 instances, which then will allow anyone with the corresponding private key to 
connect directly to the systems via SSH.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create multiple EC2 instances and a VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>: 

- Adds a public SSH key to the EC2 for 60 seconds.

References:

- https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/#hands-on-keyboard-activity-begins
- https://sysdig.com/blog/2023-global-cloud-threat-report/
- https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.lateral-movement.ec2-instance-connect
```
## Detection


Identify, through CloudTrail's <code>SendSSHPublicKey</code> event, when a user is adding an SSH key to multiple EC2 instances. Sample event:

```
{
  "eventSource": "ec2-instance-connect.amazonaws.com",
  "eventName": "SendSSHPublicKey",
  "requestParameters": {
    "instanceId": "i-123456",
    "instanceOSUser": "ec2-user",
    "sSHPublicKey": "ssh-ed25519 ..."
  }
}
```


