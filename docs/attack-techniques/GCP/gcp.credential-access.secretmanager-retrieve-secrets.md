---
title: Retrieve a High Number of Secret Manager secrets
---

# Retrieve a High Number of Secret Manager secrets


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Credential Access



## Description


Retrieves a high number of Secret Manager secrets in a short timeframe, through the AccessSecretVersion API.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create multiple secrets in Secret Manager.

<span style="font-variant: small-caps;">Detonation</span>: 

- Enumerate the secrets through the ListSecrets API
- Retrieve each secret value, one by one through the AccessSecretVersion API


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.credential-access.secretmanager-retrieve-secrets
```
## Detection

Cloud Audit Logs event corresponding to accessing a secret's value is <code>AccessSecretVersion</code>. 
It is considered [data access event](https://cloud.google.com/secret-manager/docs/audit-logging), and needs to be explicitly enabled for the Secret Manager API. 

Sample event:

```json hl_lines="18 20 25"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "requestMetadata": {
      "callerIp": "7.7.7.7",
      "callerSuppliedUserAgent": "stratus-red-team_4fbc5d44-9c4f-469f-a15b-0c85e6ad3241 grpc-go/1.70.0,gzip(gfe)",
      "requestAttributes": {
        "time": "2025-02-02T22:56:34.343726445Z",
        "auth": {}
      },
      "destinationAttributes": {}
    },
    "serviceName": "secretmanager.googleapis.com",
    "methodName": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
    "authorizationInfo": [
      {
        "permission": "secretmanager.versions.access",
        "granted": true,
        "resourceAttributes": {
          "service": "secretmanager.googleapis.com",
          "name": "projects/victim-project/secrets/stratus-red-team-retrieve-secret-8/versions/latest",
          "type": "secretmanager.googleapis.com/SecretVersion"
        },
        "permissionType": "DATA_READ"
      }
    ],
    "resourceName": "projects/victim-project/secrets/stratus-red-team-retrieve-secret-8/versions/latest",
    "request": {
      "name": "projects/victim-project/secrets/stratus-red-team-retrieve-secret-8/versions/latest",
      "@type": "type.googleapis.com/google.cloud.secretmanager.v1.AccessSecretVersionRequest"
    }
  },
  "resource": {
    "type": "audited_resource",
    "labels": {
      "method": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
      "project_id": "victim-project",
      "service": "secretmanager.googleapis.com"
    }
  }
}
```

References:

- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-services/gcp-secrets-manager-enum.html



