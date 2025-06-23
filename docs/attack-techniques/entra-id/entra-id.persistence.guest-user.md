---
title: Create Guest User
---

# Create Guest User




Platform: Entra ID

## Mappings

- MITRE ATT&CK
    - Persistence



## Description


Invites an external guest user in the tenant.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>:

- Invite guest user (without generating an invitation email)

References:

- https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/inviting-external-users/
- https://derkvanderwoude.medium.com/azure-subscription-hijacking-and-cryptomining-86c2ac018983
- https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf

!!! note

	By default, Stratus Red Team invites the e-mail <code>stratus-red-team@example.com</code>. However, you can override
	this behavior by setting the environment variable <code>STRATUS_RED_TEAM_ATTACKER_EMAIL</code>, for instance:

	```bash
	export STRATUS_RED_TEAM_ATTACKER_EMAIL="you@domain.tld"
	stratus detonate entra-id.persistence.guest-user
	```


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate entra-id.persistence.guest-user
```
## Detection


Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the specific activity types:

- <code>Add user</code>
- <code>Invite external user</code>
- <code>Add user sponsor</code>

When the invited user accepts the invite, an additional event <code>Redeem external user invite</code> is logged. 

Sample events, shortened for clarity:

```json
{
  "category": "UserManagement",
  "result": "success",
  "activityDisplayName": "Invite external user",
  "loggedByService": "Invited Users",
  "initiatedBy": {
    "user": {
      "userPrincipalName": "<inviter@tenant.tld>",
    }
  },
  "userAgent": "",
  "targetResources": [
    {
      "displayName": "<invited user display name>",
      "type": "User",
      "userPrincipalName": "<invited-user-email>#EXT#@<tenant.tld>",
      "groupType": null,
      "modifiedProperties": []
    }
  ],
  "additionalDetails": [
    {
      "key": "invitedUserEmailAddress",
      "value": "<invited-user-email>"
    }
  ]
}
{
  "category": "UserManagement",
  "result": "success",
  "resultReason": null,
  "activityDisplayName": "Redeem external user invite",
  "loggedByService": "B2B Auth",
  "initiatedBy": {
    "user": {
      "userPrincipalName": "<invited-user-email>",
      "ipAddress": "<invited-user-ip>"
    }
  },
  "targetResources": [
    {
      "id": "d042c4fe-5dd1-44a2-883a-eede6c10608f",
      "displayName": "UPN: <invited-user-email>#EXT#<tenant.tld>, Email: <invited-user-email>, InvitationId: 4c93fc70-169a-411f-8cf7-aff732f8c7b9, Source: One Time Passcode",
      "type": "User",
      "userPrincipalName": "<invited-user-email>#EXT#<tenant.tld>"
    }
  ]
}
```


