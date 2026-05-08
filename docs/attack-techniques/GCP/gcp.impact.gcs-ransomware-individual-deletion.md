---
title: GCS Ransomware through individual file deletion
---

# GCS Ransomware through individual file deletion




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates GCS ransomware activity that empties a Cloud Storage bucket through individual object deletion, then uploads a ransom note.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cloud Storage bucket, with object versioning enabled
- Create a number of objects in the bucket, with random content and extensions

<span style="font-variant: small-caps;">Detonation</span>:

- List all available objects and their versions in the bucket
- Delete all objects in the bucket one by one, including all noncurrent versions, using [objects.delete](https://cloud.google.com/storage/docs/json_api/v1/objects/delete)
- Upload a ransom note to the bucket

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket.

References:

- [Detecting and Hunting for Cloud Ransomware Part 2: GCP GCS (Panther)](https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-2-gcp-gcs)
- [Mitigate ransomware attacks using Google Cloud (Google Cloud Architecture Center)](https://cloud.google.com/architecture/security/mitigating-ransomware-attacks)


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.gcs-ransomware-individual-deletion
```
## Detection


You can detect ransomware activity by identifying abnormal patterns of objects being downloaded or deleted in the bucket.
This can be done through GCS [Data Access audit logs](https://cloud.google.com/storage/docs/audit-logging) by monitoring for high volumes of <code>storage.objects.delete</code> events
attributed to a single principal in a short time window.

Note that GCS Data Access logs are not enabled by default and must be [explicitly enabled](https://cloud.google.com/storage/docs/audit-logging#enabling) at the project or organization level. The audit log does not surface the object generation/version that was deleted, so a defender cannot tell from logs alone whether noncurrent versions were also wiped — only that N independent delete operations occurred.

Sample audit log event for <code>storage.objects.delete</code>, shortened for readability:

```json hl_lines="4 6 11"
{
  "protoPayload": {
    "serviceName": "storage.googleapis.com",
    "methodName": "storage.objects.delete",
    "resourceName": "projects/_/buckets/target-bucket/objects/target-object-key",
    "authorizationInfo": [
      { "permission": "storage.objects.delete", "granted": true }
    ],
    "authenticationInfo": {
      "principalEmail": "attacker@example.com"
    }
  },
  "resource": {
    "type": "gcs_bucket",
    "labels": {
      "bucket_name": "target-bucket"
    }
  }
}
```


