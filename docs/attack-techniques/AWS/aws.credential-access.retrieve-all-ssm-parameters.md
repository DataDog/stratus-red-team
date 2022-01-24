---
title: Retrieve And Decrypt SSM Parameters
---

# Retrieve And Decrypt SSM Parameters


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Retrieves and decrypts a high number (30) of SSM Parameters available in an AWS region.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create multiple SSM Parameters

<span style="font-variant: small-caps;">Detonation</span>: 

- Use ssm:DescribeParameters to list SSM Parameters in the current region
- Use ssm:GetParameters by batch of 10 (maximal supported value) to retrieve the values of the SSM Parameters


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.retrieve-all-ssm-parameters
```