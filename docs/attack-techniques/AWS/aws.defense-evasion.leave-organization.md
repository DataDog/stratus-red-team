---
title: Attempt to Leave the AWS Organization
---

# Attempt to Leave the AWS Organization


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Attempts to leave the AWS Organization (unsuccessfully - will hit an AccessDenied error). 
Security configurations are often defined at the organization level (GuardDuty, SecurityHub, CloudTrail...). 
Leaving the organization can disrupt or totally shut down these controls.


<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an IAM role without permissions to run organizations:LeaveOrganization

<span style="font-variant: small-caps;">Detonation</span>: 

- Call organization:LeaveOrganization to simulate an attempt to leave the AWS Organization.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.leave-organization
```