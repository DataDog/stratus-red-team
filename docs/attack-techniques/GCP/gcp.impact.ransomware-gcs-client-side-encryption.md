---
title: Ransomware Simulation — Encrypt GCS Objects Client-Side
---

# Ransomware Simulation — Encrypt GCS Objects Client-Side




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates a GCS ransomware attack that encrypts objects in place using AES-256-GCM
client-side encryption rather than simply deleting them. For each object the attack
downloads the content into memory, encrypts it with a hardcoded key, uploads the
ciphertext under the original name with an <code>.enc</code> suffix, and deletes the
plaintext original. Finally a ransom note is uploaded.

This pattern is used by sophisticated ransomware operators who want to hold data
hostage rather than destroy it — the victim retains storage costs and sees encrypted
objects, but cannot access plaintext without the attacker's key.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCS bucket with 10 test objects containing simulated sensitive data

<span style="font-variant: small-caps;">Detonation</span>:

- List all objects in the bucket
- For each object: download, encrypt with AES-256-GCM, re-upload as
  <code>&lt;name&gt;.enc</code>, delete original
- Upload <code>RANSOM_NOTE.txt</code>

References:

- https://cloud.google.com/storage/docs/encryption
- https://cloud.google.com/storage/docs/json_api/v1/objects


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.ransomware-gcs-client-side-encryption
```
## Detection


Identify a pattern of paired GCS object writes and deletes on the same bucket in a
short time window by monitoring for <code>storage.objects.create</code> and
<code>storage.objects.delete</code> events in GCP Data Access audit logs where the
new object names carry an <code>.enc</code> suffix and are followed by deletion of
the corresponding plaintext objects.


