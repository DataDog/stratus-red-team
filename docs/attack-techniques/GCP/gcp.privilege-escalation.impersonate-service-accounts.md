---
title: Impersonate GCP Service Accounts
---

# Impersonate GCP Service Accounts


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Privilege Escalation

## Description


Attempts to impersonate several GCP service accounts. Service account impersonation in GCP allows to retrieve
temporary credentials allowing to act as a service account.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create 10 GCP service accounts
- Grant the current user <code>roles/iam.serviceAccountTokenCreator</code> on one of these service accounts

<span style="font-variant: small-caps;">Detonation</span>:

- Attempt to impersonate each of the service accounts
- One impersonation request will succeed, simulating a successful privilege escalation


!!! info

    GCP takes a few seconds to propagate the new <code>roles/iam.serviceAccountTokenCreator</code> role binding to the current user.

    It is recommended to first warm up this attack technique (<code>stratus warmup ...</code>), wait for 30 seconds, then detonate it.

References:

- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/
- https://cloud.google.com/iam/docs/impersonating-service-accounts


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.privilege-escalation.impersonate-service-accounts
```
## Detection


Using GCP Admin Activity audit logs event <code>GenerateAccessToken</code>.

Sample successful event (shortened for clarity):

```json hl_lines="12 21"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "user@domain.tld",
      "principalSubject": "user:user@domain.tld"
    },
    "requestMetadata": {
      "callerIp": "(calling IP)",
    },
    "serviceName": "iamcredentials.googleapis.com",
    "methodName": "GenerateAccessToken",
    "authorizationInfo": [
      {
        "permission": "iam.serviceAccounts.getAccessToken",
        "granted": true,
        "resourceAttributes": {}
      }
    ],
    "request": {
      "name": "projects/-/serviceAccounts/impersonated-service-account@project-id.iam.gserviceaccount.com",
      "@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest"
    }
  },
  "resource": {
    "type": "service_account",
    "labels": {
      "unique_id": "105711361070066902665",
      "email_id": "impersonated-service-account@project-id.iam.gserviceaccount.com",
      "project_id": "project-id"
    }
  },
  "severity": "INFO",
  "logName": "projects/project-id/logs/cloudaudit.googleapis.com%2Fdata_access"
}
```


When impersonation fails, the generated event **does not contain** the identity of the caller, as explained in the
[GCP documentation](https://cloud.google.com/logging/docs/audit#user-id):

> For privacy reasons, the caller's principal email address is redacted from an audit log if the operation is 
> read-only and fails with a "permission denied" error. The only exception is when the caller is a service 
> account in the Google Cloud organization associated with the resource; in this case, the email address isn't redacted.

Sample **unsuccessful** event (shortened for clarity):

```json hl_lines="5 6 13 38"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "status": {
      "code": 7,
      "message": "PERMISSION_DENIED"
    },
    "authenticationInfo": {},
    "requestMetadata": {
      "callerIp": "(calling IP)"
    },
    "serviceName": "iamcredentials.googleapis.com",
    "methodName": "GenerateAccessToken",
    "authorizationInfo": [
      {
        "permission": "iam.serviceAccounts.getAccessToken",
        "resourceAttributes": {}
      }
    ],
    "resourceName": "projects/-/serviceAccounts/103566171230474107362",
    "request": {
      "@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest",
      "name": "projects/-/serviceAccounts/target-service-account@project-id.iam.gserviceaccount.com"
    },
    "metadata": {
      "identityDelegationChain": [
        "projects/-/serviceAccounts/target-service-account@project-id.iam.gserviceaccount.com"
      ]
    }
  },
  "resource": {
    "type": "service_account",
    "labels": {
      "email_id": "target-service-account@project-id.iam.gserviceaccount.com",
      "project_id": "project-id"
    }
  },
  "severity": "ERROR",
  "logName": "projects/project-id/logs/cloudaudit.googleapis.com%2Fdata_access"
}
```

Some detection strategies may include:

* Alerting on unsuccessful impersonation attempts
* Alerting when the same IP address / user-agent attempts to impersonate several service accounts in a 
short amount of time (successfully or not)


