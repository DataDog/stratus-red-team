---
title: Elevate to User Access Administrator at Root Scope
---

# Elevate to User Access Administrator at Root Scope




Platform: Azure

## Mappings

- MITRE ATT&CK
    - Privilege Escalation



## Description


Elevates the current principal to the User Access Administrator role at root scope (/),
by abusing the "Access management for Azure resources" capability available to Global Administrators in Entra ID.

This technique allows a Global Administrator to gain control over all Azure subscriptions and management groups
in the tenant, enabling arbitrary role assignments across all Azure resources.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>:

- Call the <code>elevateAccess</code> REST API endpoint, which assigns the User Access Administrator role at root scope (/) to the current principal

Revert:

- Remove the User Access Administrator role assignment at root scope (/)
If you are getting a 403 error when attempting to revert, you may need to refresh your credentials with <code>az login</code>

References:

- https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin
- https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/
- https://www.invictus-ir.com/nieuws/the-azure-log-you-probably-didnt-know-existed
- https://permiso.io/blog/azures-apex-permissions-elevate-access-the-logs-security-teams-overlook


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.privilege-escalation.root-user-access-administrator
```
## Detection


Identify when the <code>elevateAccess</code> action is called through either the Entra ID Audit Logs or the Azure Activity Log.

Sample Entra ID Audit Log entry:

``` json hl_lines="2 5"
{
  "operationName": "User has elevated their access to User Access Administrator for their Azure Resources",
  "category": "AuditLogs",
  "properties": {
    "category": "AzureRBACRoleManagementElevateAccess",
    "activityDisplayName": "User has elevated their access to User Access Administrator for their Azure Resources",
    "loggedByService": "Azure RBAC (Elevated Access)",
    "result": "success",
    "initiatedBy": {
      "user": {
      "id": "00000000-0000-0000-0000-000000000000",
      "userPrincipalName": "user@example.com",
      "ipAddress": "1.2.3.4"
      }
    }
  }
}
  
```

Sample Azure Activity Log entry:

``` json hl_lines="3 8"
{
  "authorization": {
    "action": "Microsoft.Authorization/elevateAccess/action",
    "scope": "/providers/Microsoft.Authorization"
  },
  "caller": "user@example.com",
  "operationName": {
    "value": "Microsoft.Authorization/elevateAccess/action",
    "localizedValue": "Assigns the caller to User Access Administrator role"
  },
  "properties": {
    "statusCode": "OK",
    "eventCategory": "Administrative",
    "entity": "/providers/Microsoft.Authorization",
    "message": "Microsoft.Authorization/elevateAccess/action",
  }
  "status": {
    "value": "Succeeded"
  }
}
```


