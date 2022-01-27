---
title: Exfiltrate an AMI by Sharing It
---

# Exfiltrate an AMI by Sharing It


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates an AMI by sharing it with an external AWS account.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an AMI.

<span style="font-variant: small-caps;">Detonation</span>: 

- Share the AMI with an external, fictitious AWS account.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.ec2-share-ami
```