---
title: Stop CloudTrail Trail
---

# Stop CloudTrail Trail


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

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
stratus detonate aws.defense-evasion.cloudtrail-stop
```