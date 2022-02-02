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
stratus detonate aws.defense-evasion.cloudtrail-delete
```
## Detection


Identify when a CloudTrail trail is deleted, through CloudTrail's <code>DeleteTrail</code> event.

GuardDuty also provides a dedicated finding type, [Stealth:IAMUser/CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled).


