---
title: Exfiltrate an AMI by Sharing It
---

# Exfiltrate an AMI by Sharing It 

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
stratus detonate aws.exfiltration.ami-sharing
```