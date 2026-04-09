---
title: Ransomware Simulation — Delete All GCS Objects in Batch
---

# Ransomware Simulation — Delete All GCS Objects in Batch




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates a GCS ransomware attack by deleting all objects in a bucket
concurrently (in parallel goroutines) and uploading a ransom note. This
mirrors the pattern used by ransomware that bulk-deletes cloud storage
to maximize impact and generate storage deletion billing events for the victim.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCS bucket with 50 test objects

<span style="font-variant: small-caps;">Detonation</span>:

- List all objects in the bucket
- Delete all objects concurrently using goroutines
- Upload a ransom note as <code>RANSOM_NOTE.txt</code>

References:

- https://cloud.google.com/storage/docs/deleting-objects
- https://cloud.google.com/storage/docs/json_api/v1/objects/delete
- https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-2-gcp-gcs
- https://www.paloaltonetworks.com/blog/prisma-cloud/ransomware-data-protection-cloud/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.ransomware-gcs-batch-deletion
```
## Detection


Identify a burst of GCS object deletions by monitoring for a high volume of
<code>storage.objects.delete</code> events in GCP Data Access audit logs in
a short time window, particularly when followed by the creation of a file
named <code>RANSOM_NOTE.txt</code>.


