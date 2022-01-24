---
title: Stop CloudTrail Trail
---

# Stop CloudTrail Trail 

Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Stops a CloudTrail Trail from logging. Simulates an attacker disrupting CloudTrail logging.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a CloudTrail Trail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Call cloudtrail:StopLogging to stop CloudTrail logging.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.stop-cloudtrail
```