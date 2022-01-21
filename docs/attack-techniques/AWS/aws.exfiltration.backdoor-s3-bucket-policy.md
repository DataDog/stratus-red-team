---
title: Backdoor an S3 Bucket via its Bucket Policy
---

# Backdoor an S3 Bucket via its Bucket Policy 

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates data from an S3 bucket by backdooring its bucket policy to allow access from an external AWS account.

Warm-up: Creates an S3 bucket.

Detonation: Backdoors the S3 bucket policy.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.backdoor-s3-bucket-policy
```