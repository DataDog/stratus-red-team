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
stratus detonate aws.exfiltration.ec2-security-group-open-port-22-ingress
```
## Detection


You can use the CloudTrail event <code>AuthorizeSecurityGroupIngress</code> when:

- <code>requestParameters.cidrIp</code> is <code>0.0.0.0/0</code> (or an unknown external IP)
- and <code>requestParameters.fromPort</code>/<code>requestParameters.toPort</code> is not a commonly exposed port or corresponds to a known administrative protocol such as SSH or RDP


