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

Attempts to enumerate permissions of a compromised GCP service account by
making a large number of API calls across various GCP services, generating many
<code>PERMISSION_DENIED</code> (status code 7) errors in GCP Cloud Audit Logs.

This simulates an attacker who has compromised a service account key and is enumerating what the
service account has access to, similar to tools such as
[gcpwn](https://github.com/NetSPI/gcpwn),
[Bruteforce-GCP-Permissions](https://github.com/carlospolop/Bruteforce-GCP-Permissions),
or [GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation).

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCP service account with no permissions
- Create a service account key

<span style="font-variant: small-caps;">Detonation</span>:

- Use the service account key to call 501 GCP API endpoints across multiple services (Compute Engine, IAM, Storage, KMS, Cloud Functions, and more)
- All calls result in <code>PERMISSION_DENIED</code> errors

References:

- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/
- https://github.com/NetSPI/gcpwn
- https://hackingthe.cloud/gcp/enumeration/enumerate_service_account_permissions/
- https://www.datadoghq.com/blog/monitoring-gcp-audit-logs/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.discovery.enumerate-permissions
```
## Detection

Identify a large number of GCP API calls resulting in <code>PERMISSION_DENIED</code> (status code 7) errors
originating from a single service account in a short time window.

!!! warning

    By default, GCP does not log <code>PERMISSION_DENIED</code> errors for read operations because
    <a href="https://cloud.google.com/logging/docs/audit#data-access">Data Access audit logs</a> are disabled.
    You need to <a href="https://cloud.google.com/logging/docs/audit/configure-data-access">enable Data Access audit logs</a>
    for the technique to generate logs that can be detected.

In GCP Cloud Audit Logs, look for events where:

- <code>protoPayload.status.code</code> is <code>7</code> (PERMISSION_DENIED)
- A single <code>protoPayload.authenticationInfo.principalEmail</code> generates a high volume of such events
- The events span multiple <code>protoPayload.serviceName</code> values (indicating broad enumeration)

Sample GCP Cloud Audit Log event (shortened for clarity):

```json
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "status": {
      "code": 7,
      "message": "PERMISSION_DENIED"
    },
    "authenticationInfo": {
      "principalEmail": "stratus-red-team-ep-sa@project-id.iam.gserviceaccount.com",
      "serviceAccountKeyName": "//iam.googleapis.com/projects/project-id/serviceAccounts/stratus-red-team-ep-sa@project-id.iam.gserviceaccount.com/keys/key-id"
    },
    "requestMetadata": {
      "callerIp": "1.2.3.4"
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.instances.list",
    "authorizationInfo": [
      {
        "permission": "compute.instances.list",
        "granted": false,
        "resource": "projects/project-id"
      }
    ]
  }
}
```

