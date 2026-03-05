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

- Call the elevateAccess REST API endpoint, which assigns the User Access Administrator role at root scope (/) to the current principal

Revert:

- Remove the User Access Administrator role assignment at root scope (/)

References:

- https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin
- https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/
- https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.privilege-escalation.root-user-access-administrator
```
## Detection


Identify when the <code>elevateAccess</code> action is called through either the Entra ID Audit Logs or the Azure Activity Log.

Sample Entra ID Audit Log entry (sensitive fields redacted), filtering on service <code>Azure RBAC (Elevated Access)</code>:

```json hl_lines="1 3"
{
  "activityDisplayName": "User has elevated their access to User Access Administrator for their Azure Resources",
  "category": "AzureRBACRoleManagementElevateAccess",
  "loggedByService": "Azure RBAC (Elevated Access)",
  "result": "success",
  "additionalDetails": [
    { "key": "OperationName", "value": "Microsoft.Authorization/elevateAccess/action" },
    { "key": "Resource",      "value": "/providers/Microsoft.Authorization" }
  ],
  "initiatedBy": {
    "user": {
      "id": "00000000-0000-0000-0000-000000000000",
      "userPrincipalName": "user@example.com",
      "ipAddress": "1.2.3.4"
    }
  }
}
```

Sample Azure Activity Log entry (sensitive fields redacted):

```json hl_lines="2 8"
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
  "status": {
    "value": "Succeeded"
  }
}
```

Microsoft Sentinel provides a built-in analytics rule <b>Azure RBAC (Elevate Access)</b> to detect this behavior using the <code>AuditLogs</code> table.


