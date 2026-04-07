---
title: Disable a GCP Log Sink
---

# Disable a GCP Log Sink


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Defense Evasion



## Description


Disables a Cloud Logging sink that exports audit logs to a storage destination.
Simulates an attacker temporarily halting audit log export to impair detection,
without permanently destroying the sink configuration.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCS bucket
- Create a log sink exporting audit logs (<code>cloudaudit.googleapis.com</code>) to the bucket

<span style="font-variant: small-caps;">Detonation</span>:

- Disable the log sink by setting its <code>disabled</code> field to <code>true</code>

Revert:

- Re-enable the log sink by setting its <code>disabled</code> field back to <code>false</code>

References:

- https://cloud.google.com/logging/docs/export/configure_export_v2
- https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks/update
- https://attack.mitre.org/techniques/T1562/008/
- https://redcanary.com/threat-detection-report/trends/cloud-attacks/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.defense-evasion.disable-logging-sink
```
## Detection


Identify when a log sink is updated using the GCP Admin Activity audit log event
<code>google.logging.v2.ConfigServiceV2.UpdateSink</code>. Inspect the request to check
whether the <code>disabled</code> field was set to <code>true</code>.


