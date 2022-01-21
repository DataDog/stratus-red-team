---
title: Delete a CloudTrail Trail
---

# Delete a CloudTrail Trail 

Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Delete a CloudTrail trail.

Warm-up: Creates a CloudTrail trail.

Detonation: Deletes the CloudTrail trail.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.delete-cloudtrail
```