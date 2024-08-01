---
title: S3 Ransomware through client-side encryption
---

# S3 Ransomware through client-side encryption




Platform: AWS

## MITRE ATT&CK Tactics


- Impact

## Description


Simulates S3 ransomware activity that encrypts files in a bucket with a static key, through S3 [client-side encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingClientSideEncryption.html) feature.
<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an S3 bucket
- Create a number of files in the bucket, with random content and extensions

<span style="font-variant: small-caps;">Detonation</span>: 

- List all objects in the bucket
- Overwrite every file in the bucket with an encrypted version, using [S3 client-side encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingClientSideEncryption.html)
- Upload a ransom note to the bucket

References:

- https://www.firemon.com/what-you-need-to-know-about-ransomware-in-aws/
- https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.s3-ransomware-client-side-encryption
```
## Detection


You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or deleted in the bucket. 
In general, this can be done through [CloudTrail S3 data events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-object-level-tracking) (<code>DeleteObject</code>, <code>DeleteObjects</code>, <code>GetObject</code>, <code>CopyObject</code>),
[CloudWatch metrics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html#s3-request-cloudwatch-metrics) (<code>NumberOfObjects</code>),
or [GuardDuty findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) (<code>[Exfiltration:S3/AnomalousBehavior](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#exfiltration-s3-anomalousbehavior)</code>, <code>[Impact:S3/AnomalousBehavior.Delete](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-anomalousbehavior-delete)</code>).

Sample CloudTrail event <code>CopyObject</code>, when a file is encrypted with a client-side key:

```json hl_lines="3 9 11 12"
{
  "eventSource": "s3.amazonaws.com",
  "eventName": "CopyObject",
  "eventType": "AwsApiCall",
  "eventCategory": "Data",
  "managementEvent": false,
  "readOnly": false,
  "requestParameters": {
    "bucketName": "target bucket",
    "Host": "target bucket.s3.us-east-1.amazonaws.com",
    "x-amz-server-side-encryption-customer-algorithm": "AES256",
    "x-amz-copy-source": "target bucket/target file.txt",
    "key": "target file.txt",
    "x-id": "CopyObject"
  },
  "responseElements": {
    "x-amz-server-side-encryption-customer-algorithm": "AES256"
  },
  "resources": [
    {
      "type": "AWS::S3::Object",
      "ARN": "arn:aws:s3:::target bucket/target file.txt"
    },
    {
      "accountId": "012345678901",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::target bucket"
    }
  ]
}
```




