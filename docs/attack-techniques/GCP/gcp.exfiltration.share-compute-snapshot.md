---
title: Exfiltrate Compute Disk by sharing a snapshot
---

# Exfiltrate Compute Disk by sharing a snapshot


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Exfiltrates a Compute Disk by sharing a snapshot with a fictitious attacker account.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Compute Disk and a Snapshot

<span style="font-variant: small-caps;">Detonation</span>:

- Set the IAM policy of the snapshot so that the attacker account has permissions to access it

!!! note

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to stratusredteam@gmail.com by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>STRATUS_RED_TEAM_ATTACKER_EMAIL</code>, for instance:

	```bash
	export STRATUS_RED_TEAM_ATTACKER_EMAIL="your-own-gmail-account@gmail.com"
	stratus detonate gcp.exfiltration.share-compute-snapshot
	```


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.exfiltration.share-compute-snapshot
```
## Detection


You can detect when someone changes the IAM policy of a Compute Snapshot, using the GCP Admin Activity audit logs event <code>v1.compute.snapshots.setIamPolicy</code>. Here's a sample event, shortened for clarity:

```json hl_lines="18 20 25""
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "user-sharing-the-snapshot@domain.tld",
      "principalSubject": "user:user-sharing-the-snapshot@domain.tld"
    },
    "requestMetadata": {
      "callerIp": "34.33.32.31",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/..."
    },
    "resourceName": "projects/victim-project/global/snapshots/stratus-red-team-victim-snapshot",
    "request": {
      "policy": {
        "version": "3",
        "bindings": [
          {
            "role": "roles/owner",
            "members": [
              "user:attacker@gmail.com"
            ]
          }
        ]
      },
      "@type": "type.googleapis.com/compute.snapshots.setIamPolicy"
    }
  }
}
```

Based on these events, detection strategies may include:

- Alerting when the IAM policy of a Compute Snapshot is changed, especially if such a sharing mechanism is not part of your normal operations. Sample GCP Logs Explorer query:

```sql
protoPayload.methodName="v1.compute.snapshots.setIamPolicy"
```


