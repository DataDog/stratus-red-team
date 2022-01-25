---
title: Disable CloudTrail Logging Through Event Selectors
---

# Disable CloudTrail Logging Through Event Selectors


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Disrupt CloudTrail Logging by creating an event selector on the Trail, filtering out all management events.

Reference: https://github.com/RhinoSecurityLabs/Cloud-Security-Research/tree/master/AWS/cloudtrail_guardduty_bypass

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a CloudTrail trail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create a CloudTrail event selector to disable management events, through cloudtrail:PutEventSelectors


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.cloudtrail-event-selectors
```