---
title: Open Ingress Port 22 on a Security Group
---

# Open Ingress Port 22 on a Security Group 

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Opens ingress traffic on port 22 from the Internet (0.0.0.0/0).

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a VPC and a security group inside it.

<span style="font-variant: small-caps;">Detonation</span>: 

- Call ec2:AuthorizeSecurityGroupIngress to allow ingress traffic on port 22 from 0.0.0.0/0.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.open-port-22-ingress-on-security-group
```