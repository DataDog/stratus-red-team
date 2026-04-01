---
title: Backdoor a GCS Bucket via Overly Permissive IAM Policy
---

# Backdoor a GCS Bucket via Overly Permissive IAM Policy


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Grants public read access to a GCS bucket by adding an IAM binding that allows
<code>allUsers</code> to read all objects. This simulates an attacker who has
compromised a service account with Storage Admin rights and uses it to exfiltrate
data by making the bucket publicly accessible.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a private GCS bucket with 3 test objects

<span style="font-variant: small-caps;">Detonation</span>:

- Add an IAM binding granting <code>roles/storage.objectViewer</code> to
  <code>allUsers</code> on the bucket, making all objects publicly readable

Revert:

- Remove the <code>allUsers</code> IAM binding from the bucket

References:

- https://cloud.google.com/storage/docs/access-control/iam
- https://cloud.google.com/storage/docs/json_api/v1/buckets/setIamPolicy
- https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/
- https://www.praetorian.com/blog/cloud-data-exfiltration-via-gcp-storage-buckets-and-how-to-prevent-it/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.exfiltration.backdoor-gcs-bucket
```
## Detection


Identify when a GCS bucket IAM policy is modified to grant access to
<code>allUsers</code> or <code>allAuthenticatedUsers</code> by monitoring for
<code>storage.setIamPermissions</code> events in GCP Data Access audit logs where
the request includes a binding with member <code>allUsers</code>.


