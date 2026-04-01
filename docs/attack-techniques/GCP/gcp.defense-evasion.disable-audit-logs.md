---
title: Disable Data Access Audit Logs for a GCP Service
---

# Disable Data Access Audit Logs for a GCP Service




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Defense Evasion



## Description


Removes the Data Access audit log configuration for Cloud Storage from the project
IAM policy. Data Access audit logs record data access operations such as reads and
writes to GCS objects. Disabling them reduces an attacker's visibility footprint in
Cloud Logging.

<span style="font-variant: small-caps;">Warm-up</span>:

- Snapshot the current project IAM policy (including any pre-existing audit config
  for <code>storage.googleapis.com</code>) so it can be restored on revert

<span style="font-variant: small-caps;">Detonation</span>:

- Set a DATA_READ and DATA_WRITE <code>auditConfig</code> entry for
  <code>storage.googleapis.com</code> (overwriting any existing config)
- Remove the <code>auditConfig</code> entry for <code>storage.googleapis.com</code> from the
  project IAM policy via the Cloud Resource Manager API

Revert:

- Restore the exact <code>auditConfig</code> that existed before detonation (including
  any custom log types or exempted members), or leave the config absent if it was
  not present before

References:

- https://cloud.google.com/logging/docs/audit/configure-data-access
- https://cloud.google.com/resource-manager/reference/rest/v3/projects/setIamPolicy
- https://attack.mitre.org/techniques/T1562/008/
- https://redcanary.com/threat-detection-report/trends/cloud-attacks/
- https://www.sysdig.com/blog/suspicious-activity-gcp-audit-logs


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.defense-evasion.disable-audit-logs
```
## Detection


Identify when Data Access audit log configuration is removed from the project IAM policy
by monitoring for <code>SetIamPolicy</code> events in GCP Admin Activity audit logs where
the request removes or reduces <code>auditConfigs</code> entries.


