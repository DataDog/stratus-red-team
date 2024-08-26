---
title: S3 Ransomware through individual file deletion
---

# S3 Ransomware through individual file deletion




Platform: AWS

## MITRE ATT&CK Tactics


- Impact

## Description


Simulates S3 ransomware activity that empties a bucket through individual file deletion, then uploads a ransom note.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an S3 bucket, with versioning enabled
- Create a number of files in the bucket, with random content and extensions

<span style="font-variant: small-caps;">Detonation</span>: 

- List all available objects and their versions in the bucket
- Delete all objects in the bucket one by one, using [DeleteObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html)
- Upload a ransom note to the bucket

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket.

References:

- [The anatomy of a ransomware event targeting S3 (re:Inforce, 2022)](https://d1.awsstatic.com/events/aws-reinforce-2022/TDR431_The-anatomy-of-a-ransomware-event-targeting-data-residing-in-Amazon-S3.pdf)
- [The anatomy of ransomware event targeting data residing in Amazon S3 (AWS Security Blog)](https://aws.amazon.com/blogs/security/anatomy-of-a-ransomware-event-targeting-data-in-amazon-s3/)
- [Ransomware in the cloud](https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82)
- https://www.firemon.com/what-you-need-to-know-about-ransomware-in-aws/
- https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
- https://www.invictus-ir.com/news/ransomware-in-the-cloud
- https://dfir.ch/posts/aws_ransomware/
- https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/
- https://unit42.paloaltonetworks.com/shinyhunters-ransomware-extortion/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.s3-ransomware-individual-deletion
```
## Detection


You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or deleted in the bucket. 
In general, this can be done through [CloudTrail S3 data events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-object-level-tracking) (<code>DeleteObject</code>, <code>DeleteObjects</code>, <code>GetObject</code>),
[CloudWatch metrics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html#s3-request-cloudwatch-metrics) (<code>NumberOfObjects</code>),
or [GuardDuty findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) (<code>[Exfiltration:S3/AnomalousBehavior](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#exfiltration-s3-anomalousbehavior)</code>, <code>[Impact:S3/AnomalousBehavior.Delete](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#impact-s3-anomalousbehavior-delete)</code>).

Sample CloudTrail event <code>DeleteObject</code>, shortened for readability:

```json hl_lines="3 8 10"
{
  "eventSource": "s3.amazonaws.com",
  "eventName": "DeleteObject",
  "eventCategory": "Data",
  "managementEvent": false,
  "readOnly": false,
  "requestParameters": {
    "bucketName": "target-bucket",
    "Host": "target-bucket.s3.us-east-1.amazonaws.com",
    "key": "target-object-key",
    "x-id": "DeleteObject"
  },
  "resources": [
    {
      "type": "AWS::S3::Object",
      "ARN": "arn:aws:s3:::target-bucket/target-object-key"
    },
    {
      "accountId": "012345678901",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::target-bucket"
    }
  ],
  "eventType": "AwsApiCall",
  "recipientAccountId": "012345678901"
}
```


