---
title: Create a Trust anchor
---

# Create a Trust anchor




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a new Trust anchor.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create the Trust anchor with a fake Certificate Authority (CA).


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.rolesanywhere-create-trust-anchor
```
## Detection


		Identify when a Trust anchor is created, through CloudTrail's <code>CreateTrustAnchor</code> event.


