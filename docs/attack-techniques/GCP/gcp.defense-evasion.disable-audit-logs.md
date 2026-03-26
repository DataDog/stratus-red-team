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

- Enable Data Access audit logs (DATA_READ and DATA_WRITE) for <code>storage.googleapis.com</code>
  by adding an <code>auditConfig</code> entry to the project IAM policy

<span style="font-variant: small-caps;">Detonation</span>:

- Remove the <code>auditConfig</code> entry for <code>storage.googleapis.com</code> from the
  project IAM policy via the Cloud Resource Manager API

Revert:

- Re-add the <code>auditConfig</code> entry for <code>storage.googleapis.com</code> with DATA_READ
  and DATA_WRITE log types

References:

- https://cloud.google.com/logging/docs/audit/configure-data-access
- https://cloud.google.com/resource-manager/reference/rest/v3/projects/setIamPolicy


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.defense-evasion.disable-audit-logs
```
## Detection


Identify when Data Access audit log configuration is removed from the project IAM policy
by monitoring for <code>SetIamPolicy</code> events in GCP Admin Activity audit logs where
the request removes or reduces <code>auditConfigs</code> entries.


