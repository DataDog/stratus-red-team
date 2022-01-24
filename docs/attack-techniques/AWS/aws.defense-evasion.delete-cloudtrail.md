---
title: Delete CloudTrail Trail
---

# Delete CloudTrail Trail




Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Delete a CloudTrail trail. Simulates an attacker disrupting CloudTrail logging.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a CloudTrail trail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Delete the CloudTrail trail.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.delete-cloudtrail
```