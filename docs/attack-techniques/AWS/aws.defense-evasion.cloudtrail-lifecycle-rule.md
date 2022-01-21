---
title: CloudTrail Logs Impairment Through Lifecycle Rule
---

# CloudTrail Logs Impairment Through Lifecycle Rule 

Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Automatically delete CloudTrail logs after 1 day by setting a Lifecycle Rule on the CloudTrail S3 bucket.

References: https://www.justice.gov/usao-sdny/press-release/file/1452706/download

Warm-up: Creates a CloudTrail trail.

Detonation: Applies a 1-day retention S3 Lifecycle Rule.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.cloudtrail-lifecycle-rule
```