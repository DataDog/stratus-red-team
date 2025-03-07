---
title: GCS Ransomware through server-side encryption
---

# GCS Ransomware through server-side encryption 




Platform: GCP

## MITRE ATT&CK Tactics


- Impact 

## Description

Simulates ransomware activity that encrypt bucket objects with a static key, through server-side encryption, then uploads a ransom note.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a cloud storage bucket with versioning enabled
- Create a number of files in the bucket, with random content and extensions

<span style="font-variant: small-caps;">Detonation</span>:

- List all available objects and their versions in the bucket
- Encrypt the most recent version of every file (object) in the bucket
- Delete other versions of the object
- Upload a ransom note to the bucket

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket.

References:

- [Ransomware in the cloud](https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82)
- https://www.firemon.com/what-you-need-to-know-about-ransomware-in-aws/
- https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.gcs-ransomware-server-side-encryption
```

## Detection

You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or written in the bucket.
In general, this can be done through Cloud Logging for `storage.objects.create` and `storage.objects.delete` events.

Data Access logging for GCS bucket is disabled by default, thus we need to enable it (if not enabled).

- Go to "IAM & Admin" -> "Audit Logs"
- Locate "Google Cloud Storage"
- on "Permission Types", check the "Data write"

Sample event <code>storage.objects.delete</code>, shortened for readability:

```json 
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Fdata_access",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "methodName": "storage.objects.delete",
    "resourceName": "projects/_/buckets/my-bucket-name/objects/my-object-name.extension",
    "serviceName": "storage.googleapis.com",
  },
  "resource": {
    "type": "gcs_bucket",
  },
  "severity": "INFO"
}
```