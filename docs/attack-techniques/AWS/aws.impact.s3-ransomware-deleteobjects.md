---
title: S3 Ransomware through DeleteObjects
---

# S3 Ransomware through DeleteObjects




Platform: AWS

## MITRE ATT&CK Tactics


- Impact

## Description


Simulates S3 ransomware activity.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an S3 bucket, with versioning enabled
- Create a number of files in the bucket, with random content and extensions

<span style="font-variant: small-caps;">Detonation</span>: 

- List buckets in the account
- List objects in the target bucket
- Retrieve versioning configuration of the bucket
- Retrieve a few random files from the bucket
- Delete all objects in the bucket in one request, using [DeleteObjects](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjects.html)
- Upload a random note to the bucket

Note: Versioning does not need to be disabled, and it does not protect against ransomware. This attack technique removes all versions of the objects in the bucket.

References:

- [The anatomy of a ransomware event targeting S3 (re:Inforce, 2022)](https://d1.awsstatic.com/events/aws-reinforce-2022/TDR431_The-anatomy-of-a-ransomware-event-targeting-data-residing-in-Amazon-S3.pdf)
- [Ransomware in the cloud](https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82)


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.s3-ransomware-deleteobjects
```
## Detection


You can use the CloudTrail event <code>DeleteObjects</code> to identify when batch deletion of objects occurs, and <code>DeleteObject</code> for individual object deletion.

Note that <code>DeleteObjects</code> does not list the files being deleted or how many files are being deleted. Sample event, shortened for readability:

```json hl_lines="3 5"
{
  "eventSource": "s3.amazonaws.com",
  "eventName": "DeleteObjects",
  "requestParameters": {
    "bucketName": "target-bucket",
    "Host": "target-bucket.s3.us-east-1.amazonaws.com",
    "delete": "",
    "x-id": "DeleteObjects"
  },
  "responseElements": null,
  "readOnly": false,
  "resources": [
    {
      "type": "AWS::S3::Object",
      "ARNPrefix": "arn:aws:s3:::target-bucket/"
    },
    {
      "accountId": "012345678901",
      "type": "AWS::S3::Bucket",
      "ARN": "arn:aws:s3:::target-bucket"
    }
  ],
  "eventType": "AwsApiCall",
  "managementEvent": false,
  "recipientAccountId": "012345678901",
  "eventCategory": "Data"
}
```


