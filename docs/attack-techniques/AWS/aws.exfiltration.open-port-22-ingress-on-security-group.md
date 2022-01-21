---
title: Open Ingress Port 22 on a Security Group
---

# Open Ingress Port 22 on a Security Group 

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Opens ingress traffic on port 22 from the Internet.

Warm-up: Creates a security group.

Detonation: Calls AuthorizeSecurityGroupIngress


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.open-port-22-ingress-on-security-group
```