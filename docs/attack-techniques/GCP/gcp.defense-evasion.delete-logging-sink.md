---
title: Delete a GCP Log Sink
---

# Delete a GCP Log Sink




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Defense Evasion



## Description


Deletes a Cloud Logging sink that exports audit logs to a storage destination.
Simulates an attacker disrupting audit log export to impair forensic investigation and detection.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCS bucket
- Create a log sink exporting audit logs (<code>cloudaudit.googleapis.com</code>) to the bucket

<span style="font-variant: small-caps;">Detonation</span>:

- Delete the log sink

References:

- https://cloud.google.com/logging/docs/export/configure_export_v2
- https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudLogging/logging-sink.html
- https://attack.mitre.org/techniques/T1562/008/
- https://redcanary.com/threat-detection-report/trends/cloud-attacks/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.defense-evasion.delete-logging-sink
```
## Detection


Identify when a log sink is deleted using the GCP Admin Activity audit log event
<code>google.logging.v2.ConfigServiceV2.DeleteSink</code>.


