---
title: Backdoor a GCP Service Account through its IAM Policy
---

# Backdoor a GCP Service Account through its IAM Policy


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## MITRE ATT&CK Tactics


- Persistence

## Description


Backdoors a GCP service account by granting a fictitious attacker the ability to impersonate it and generate access temporary tokens for it.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a service account

<span style="font-variant: small-caps;">Detonation</span>:

- Backdoor the IAM policy of the service account to grant the role <code>iam.serviceAccountTokenCreator</code> to a fictitious attacker

Note that in GCP (contrary to AWS), the "IAM policy" of a service account is not granting permissions to the service account itself - rather,
it's a resource-based policy that grants permissions to other identities to impersonate the service account.

!!! info

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to stratusredteam@gmail.com by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>STRATUS_RED_TEAM_ATTACKER_EMAIL</code>, for instance:

	```bash
	export STRATUS_RED_TEAM_ATTACKER_EMAIL="your-own-gmail-account@gmail.com"
	stratus detonate gcp.persistence.backdoor-service-account-policy
	```


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.persistence.backdoor-service-account-policy
```
## Detection


You can detect when the IAM policy of a service account is updated using the GCP Admin Audit Logs event <code>google.iam.admin.v1.SetIAMPolicy</code> (sample below, shortened for clarity).

```json hl_lines="3 4 11 12 13 19 21"
{
  "protoPayload": {
    "serviceName": "iam.googleapis.com",
    "methodName": "google.iam.admin.v1.SetIAMPolicy",
    "resourceName": "projects/-/serviceAccounts/123456789",
    "serviceData": {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      "policyDelta": {
        "bindingDeltas": [
          {
            "action": "ADD",
            "role": "roles/iam.serviceAccountTokenCreator",
            "member": "user:stratusredteam@gmail.com"
          }
        ]
      }
    },
  "resource": {
    "type": "service_account",
    "labels": {
      "email_id": "stratus-red-team-bip-sa@victim-project.iam.gserviceaccount.com",
      "project_id": "victim-project"
    }
  },
  "logName": "projects/victim-project/logs/cloudaudit.googleapis.com%2Factivity",
}
```

When someone impersonates a service account, the GCP Admin Audit Logs event <code>google.iam.credentials.v1.GenerateAccessToken</code> is emitted if you explicitly
enabled <code>DATA_READ</code> events in the audit logs configuration of your project. For more information, see [Impersonate GCP Service Accounts](https://stratus-red-team.cloud/attack-techniques/GCP/gcp.privilege-escalation.impersonate-service-accounts/#detection).


