# Stops a CloudTrail trail

Platform: AWS

## MITRE ATT&CK Tactics

- Defense Evasion

## Description


Stops a CloudTrail trail from logging.

Warm-up: Creates a CloudTrail trail.

Detonation: Calls cloudtrail:StopLogging


## Instructions

```bash title="Detonate me!"
stratus detonate aws.defense-evasion.stop-cloudtrail
```