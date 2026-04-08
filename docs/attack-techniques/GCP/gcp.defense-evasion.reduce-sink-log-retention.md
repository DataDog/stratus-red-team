---
title: Reduce Log Retention Period on a Cloud Logging Sink Bucket
---

# Reduce Log Retention Period on a Cloud Logging Sink Bucket


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Defense Evasion



## Description


Sets a 1-day object lifecycle rule on the GCS bucket used by a Cloud Logging sink,
causing exported audit logs to be automatically deleted after one day.

This is the GCP equivalent of the AWS CloudTrail lifecycle rule technique: rather than
deleting the sink or disabling it (which raises an immediate alert), the attacker
quietly shortens the retention window of the underlying storage bucket to minimize
the forensic footprint of their activity.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCS bucket
- Create a log sink exporting audit logs (<code>cloudaudit.googleapis.com</code>) to the bucket

<span style="font-variant: small-caps;">Detonation</span>:

- Apply a GCS lifecycle rule on the log sink bucket that deletes all objects after 1 day

Revert:

- Remove the lifecycle rule from the bucket

References:

- https://cloud.google.com/storage/docs/lifecycle
- https://www.justice.gov/usao-sdny/press-release/file/1452706/download
- https://attack.mitre.org/techniques/T1562/008/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.defense-evasion.reduce-sink-log-retention
```
## Detection


Identify when a lifecycle rule with a short expiration is applied to a GCS bucket used
for Cloud Logging export. Monitor for <code>storage.buckets.update</code> events in
GCP Data Access audit logs where the request sets a lifecycle rule with a short
expiration on a bucket associated with a logging sink.


