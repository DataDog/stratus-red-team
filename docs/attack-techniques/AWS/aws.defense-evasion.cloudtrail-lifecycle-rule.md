---
title: CloudTrail Logs Impairment Through S3 Lifecycle Rule
---

# CloudTrail Logs Impairment Through S3 Lifecycle Rule




Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Set a 1-day retention policy on the S3 bucket used by a CloudTrail Trail, using a S3 Lifecycle Rule.

References: https://www.justice.gov/usao-sdny/press-release/file/1452706/download

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a CloudTrail trail logging to a S3 bucket.

<span style="font-variant: small-caps;">Detonation</span>: 

- Apply a S3 Lifecycle Rule automatically removing objects after 1 day.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.cloudtrail-lifecycle-rule
```
## Detection


Identify when lifecycle rule with a short expiration is applied to an S3 bucket used for CloudTrail logging.

The CloudTrail event <code>PutBucketLifecycle</code> and its attribute 
<code>requestParameters.LifecycleConfiguration.Rule.Expiration.Days</code> can be used.




