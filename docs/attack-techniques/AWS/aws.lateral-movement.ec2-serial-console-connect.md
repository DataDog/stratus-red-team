---
title: Usage of EC2 Serial Console to push SSH public key
---

# Usage of EC2 Serial Console to push SSH public key

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Lateral Movement

## Description


Simulates an attacker pushing an SSH public key to multiple EC2 instances through the EC2 Serial Console API. This allows anyone 
with the corresponding private key to connect directly to the systems via SSH.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create multiple EC2 instances and a VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>:

- Adds a public SSH key to the EC2 instances using the Serial Console API for 60 seconds.

References:

- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
- https://fwdcloudsec.org/assets/presentations/2024/europe/sebastian-walla-cloud-conscious-tactics-techniques-and-procedures-an-overview.pdf
- https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.lateral-movement.ec2-serial-console-connect
```
## Detection


Identify, through CloudTrail's <code>SendSerialConsoleSSHPublicKey</code> event, when a user is adding an SSH key to EC2 instances. Sample event:

```
{
  "eventSource": "ec2-instance-connect.amazonaws.com",
  "eventName": "SendSerialConsoleSSHPublicKey",
  "requestParameters": {
    "instanceId": "i-123456",
    "serialConsoleOSUser": "ec2-user",
    "sSHPublicKey": "ssh-ed25519 ..."
  }
}
```


