---
title: Create an IAM Roles Anywhere trust anchor
---

# Create an IAM Roles Anywhere trust anchor




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating an IAM Roles Anywhere trust anchor. 
The IAM Roles Anywhere service allows workloads that do not run in AWS to assume roles by presenting a client-side 
X.509 certificate signed by a trusted certificate authority, called a "trust anchor".

Assuming IAM Roles Anywhere is in use (i.e., that some of the IAM roles in the account have a 
[trust policy](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html#trust-policy) trusting 
the IAM Roles Anywhere service), an attacker creating a trust anchor can subsequently assume these roles.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM role that can be used by IAM Roles Anywhere (see [docs](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html#getting-started-step2))

<span style="font-variant: small-caps;">Detonation</span>: 

- Create an IAM Roles Anywhere trust anchor
- Create an IAM Roles Anywhere profile

References:

- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html
- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.rolesanywhere-create-trust-anchor
```
## Detection


Identify when a trust anchor is created, through CloudTrail's <code>CreateTrustAnchor</code> event.


