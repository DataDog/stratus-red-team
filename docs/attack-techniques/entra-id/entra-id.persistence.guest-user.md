---
title: Create Guest User for Persistent Access
---

# Create Guest User for Persistent Access




Platform: Entra ID

## MITRE ATT&CK Tactics

- Persistence

## Description
An attacker can abuse the Guest User invite process to gain persistent access to an environment, as they can invite themselves as a guest.

<span style="font-variant: small-caps;">Warm-up</span>:

- N/A, this technique does not have a warm-up stage

<span style="font-variant: small-caps;">Detonation</span>:

- Invite Guest User

References:

- https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/inviting-external-users/

!!! note

	Since the target e-mail must exist for this attack simulation to work, Stratus Red Team grants the role to stratusredteam@gmail.com by default.
	This is a real Google account, owned by Stratus Red Team maintainers and that is not used for any other purpose than this attack simulation. However, you can override
	this behavior by setting the environment variable <code>STRATUS_RED_TEAM_ATTACKER_EMAIL</code>, for instance:

	```bash
	export STRATUS_RED_TEAM_ATTACKER_EMAIL="your-own-gmail-account@gmail.com"
	stratus detonate entra-id.persistence.guest-user
	```

## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate entra-id.persistence.guest-user
```

## Detection

When someone invites a guest user in Azure AD, several events are logged in the Azure AD Activity logs:

<code>Add user</code>
<code>Invite external user</code>
<code>Add user sponsor</code>

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