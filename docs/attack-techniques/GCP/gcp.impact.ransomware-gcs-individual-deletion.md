---
title: Ransomware Simulation — Delete GCS Objects Individually
---

# Ransomware Simulation — Delete GCS Objects Individually




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates a GCS ransomware attack by deleting objects one by one sequentially
and uploading a ransom note. Unlike the batch variant, individual deletions
produce a clear sequential pattern in audit logs, making the attack more
detectable but also modeling a simpler adversary tool that lacks parallelism.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCS bucket with 10 test objects

<span style="font-variant: small-caps;">Detonation</span>:

- List all objects in the bucket
- Delete each object individually in sequence
- Upload a ransom note as <code>RANSOM_NOTE.txt</code>

References:

- https://cloud.google.com/storage/docs/deleting-objects
- https://cloud.google.com/storage/docs/json_api/v1/objects/delete


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.ransomware-gcs-individual-deletion
```
## Detection


Identify sequential GCS object deletions by monitoring for a stream of
<code>storage.objects.delete</code> events in GCP Data Access audit logs
where the same principal deletes multiple objects in rapid succession,
particularly when followed by the creation of <code>RANSOM_NOTE.txt</code>.


