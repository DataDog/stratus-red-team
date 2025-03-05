---
title: Backdoor a Cloud Storage bucket via its bucket policy
---

# Backdoor a Cloud Storage bucket via its bucket policy

<span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates data from a Cloud Storage bucket by backdooring its policy to allow access from an external, fictitious GCP account.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cloud Storage bucket

<span style="font-variant: small-caps;">Detonation</span>:

- Backdoor the IAM policy of the bucket to grant the role `storage.objectAdmin` to a fictitious attacker

!!! info

  Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to stratusredteam@gmail.com by default.
  This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
  this behavior by setting the environment variable <code>STRATUS_RED_TEAM_ATTACKER_EMAIL</code>, for instance:

  ```bash
  export STRATUS_RED_TEAM_ATTACKER_EMAIL="your-own-gmail-account@gmail.com"
  stratus detonate gcp.exfiltration.gcs-backdoor-bucket-policy
  ```


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.exfiltration.gcs-backdoor-bucket-policy
```
## Detection


Granting IAM role to account is detected as 'storage.setIamPolicy' in Cloud Logging.

Data Access logging for GCS bucket is disabled by default, thus we need to enable it (if not enabled).

- Go to "IAM & Admin" -> "Audit Logs"
- Locate "Google Cloud Storage"
- on "Permission Types", check the "Admin read"

You can use following query to filter the events:

```
resource.type="gcs_bucket"
protoPayload.serviceName="storage.googleapis.com"
protoPayload.methodName="storage.setIamPermissions"
```

Sample event (shortened for readability):

```json
{
  "logName": "projects/my-project-id/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "username@service.com",
    },
    "methodName": "storage.setIamPermissions",
    "resourceName": "projects/_/buckets/my-bucket-id",
    "serviceName": "storage.googleapis.com",
  },
  "resource": {
    "type": "gcs_bucket"
  },
  "severity": "NOTICE"
}
