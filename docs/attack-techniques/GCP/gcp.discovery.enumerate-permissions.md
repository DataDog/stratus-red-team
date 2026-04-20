---
title: Enumerate Permissions of a GCP Service Account
---

# Enumerate Permissions of a GCP Service Account


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Discovery



## Description

Enumerates permissions of a GCP service account by
calling <code>projects.testIamPermissions</code> on a large number of permissions.

This simulates an attacker who has compromised a service account key and is enumerating what the
service account has access to.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCP service account
- Grant a low-value permission set: Storage Object Viewer
- Create a service account key

<span style="font-variant: small-caps;">Detonation</span>:

- Call <code>projects.testIamPermissions</code>, with chunks of 100 permissions each time

References:

- https://securitylabs.datadoghq.com/articles/google-cloud-default-service-accounts/#enumerating-permissions-of-the-associated-service-account
- https://docs.cloud.google.com/iam/docs/reference/rest/v1/permissions/queryTestablePermissions
- https://cloud.google.com/resource-manager/reference/rest/v1/projects/testIamPermissions
- https://docs.cloud.google.com/iam/docs/roles-permissions


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.discovery.enumerate-permissions
```
## Detection

Monitor repeated calls to <code>projects.testIamPermissions</code> from the same service account.

!!! warning

    These events are in
    <a href="https://cloud.google.com/logging/docs/audit#data-access">Data Access audit logs</a>,
    which are disabled by default.
    Enable Data Access logging for Resource Manager to capture this behavior.

