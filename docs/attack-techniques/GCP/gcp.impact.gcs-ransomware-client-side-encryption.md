---
title: GCS Ransomware through client-side encryption
---

# GCS Ransomware through client-side encryption




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates GCS ransomware activity that encrypts files in a Cloud Storage bucket with a static key, through GCS [Customer-Supplied Encryption Keys](https://cloud.google.com/storage/docs/encryption/customer-supplied-keys) (CSEK).

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cloud Storage bucket
- Create a number of objects in the bucket, with random content and extensions

<span style="font-variant: small-caps;">Detonation</span>:

- List all objects in the bucket
- Rewrite every object in place with a customer-supplied AES-256 encryption key, using [objects.rewrite](https://cloud.google.com/storage/docs/json_api/v1/objects/rewrite). Once encrypted, the object can no longer be read without supplying the same key
- Upload a ransom note to the bucket

References:

- [Detecting and Hunting for Cloud Ransomware Part 2: GCP GCS (Panther)](https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-2-gcp-gcs)
- [Mitigate ransomware attacks using Google Cloud (Google Cloud Architecture Center)](https://cloud.google.com/architecture/security/mitigating-ransomware-attacks)
- [Customer-supplied encryption keys (GCS documentation)](https://cloud.google.com/storage/docs/encryption/customer-supplied-keys)


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.gcs-ransomware-client-side-encryption
```
## Detection


You can detect ransomware activity by identifying abnormal patterns of objects being rewritten in place.
The GCS rewrite API (used to encrypt an object with a customer-supplied key without changing its name) is recorded in [Data Access audit logs](https://cloud.google.com/storage/docs/audit-logging) with <code>methodName: storage.objects.create</code>

A rewrite-in-place can be distinguished from a regular upload by inspecting <code>authorizationInfo</code>: a rewrite checks <strong>both</strong> <code>storage.objects.delete</code> and <code>storage.objects.create</code> permissions on the same object, whereas a plain upload only checks <code>storage.objects.create</code>.

Note that GCS Data Access logs are not enabled by default and must be [explicitly enabled](https://cloud.google.com/storage/docs/audit-logging#enabling) at the project or organization level.

Sample audit log event for a rewrite-in-place, shortened for readability:

```json hl_lines="4 7 9 13"
{
  "protoPayload": {
    "serviceName": "storage.googleapis.com",
    "methodName": "storage.objects.create",
    "resourceName": "projects/_/buckets/target-bucket/objects/target-object-key",
    "authorizationInfo": [
      { "permission": "storage.objects.delete", "granted": true },
      { "permission": "storage.objects.create", "granted": true }
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


