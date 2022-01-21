---
title: Stop a CloudTrail Trail
---

# Stop a CloudTrail Trail 

Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Stops a CloudTrail trail from logging.

Warm-up: Creates a CloudTrail trail.

Detonation: Calls cloudtrail:StopLogging


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.stop-cloudtrail
```