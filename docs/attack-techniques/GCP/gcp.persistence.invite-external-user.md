---
title: Invite an External User to a GCP Project
---

# Invite an External User to a GCP Project


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Persistence

## Description


Persists in the GCP project by inviting an external (fictitious) user to the project. The attacker could then use the external user to access the project.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>:

- Updates the project IAM policy to grant the attacker account the role of <code>roles/editor</code>

!!! note

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to stratusredteam@gmail.com by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>STRATUS_RED_TEAM_ATTACKER_EMAIL</code>, for instance:

	```bash
	export STRATUS_RED_TEAM_ATTACKER_EMAIL="your-own-gmail-account@gmail.com"
	stratus detonate gcp.persistence.invite-external-user
	```


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.persistence.invite-external-user
```
## Detection


The Google Cloud Admin logs event <code>SetIamPolicy</code> is generated when a principal is granted non-owner permissions at the project level.

```javascript hl_lines="5 11 12 13"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "cloudresourcemanager.googleapis.com",
    "methodName": "SetIamPolicy",
    "serviceData": {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      "policyDelta": {
        "bindingDeltas": [
          {
            "action": "ADD",
            "role": "roles/editor",
            "member": "user:stratusredteam@gmail.com"
          }
        ]
      }
    },
    "request": {
      "resource": "target-project",
      "policy": {
        // ...
      },
      "@type": "type.googleapis.com/google.iam.v1.SetIamPolicyRequest"
    }
  }
}
```

Although this attack technique does not simulate it, an attacker can also 
<a href="https://support.google.com/googleapi/answer/6158846?hl=en">use the GCP console to invite an external user as owner</a> of a GCP project,
which cannot be done through the SetIamPolicy API call. In that case, an <code>InsertProjectOwnershipInvite</code> event is generated:

```json hl_lines="5 8"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "cloudresourcemanager.googleapis.com",
    "methodName": "InsertProjectOwnershipInvite",
    "resourceName": "projects/target-project",
    "request": {
      "member": "user:attacker@gmail.com",
      "projectId": "target-project",
      "@type": "type.googleapis.com/google.internal.cloud.resourcemanager.InsertProjectOwnershipInviteRequest"
    },
    "response": {
      "@type": "type.googleapis.com/google.internal.cloud.resourcemanager.InsertProjectOwnershipInviteResponse"
    }
  }
}
```



