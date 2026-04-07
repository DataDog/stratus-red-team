---
title: Backdoor Azure Managed Identity with Federated Identity Credential (FIC)
---

# Backdoor Azure Managed Identity with Federated Identity Credential (FIC)




Platform: Azure

## Mappings

- MITRE ATT&CK
    - Persistence
  - Privilege Escalation



## Description


Backdoors an existing Azure Managed Identity by creating a new Federated Identity Credential (FIC) that trusts an attacker-controlled OIDC provider.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a resource group and victim Azure Managed Identity
- Assign it the <code>Directory Readers</code> role at the tenant level (for illustration purposes)
- Create an Azure Storage account to host the attacker-controlled OIDC provider metadata

<span style="font-variant: small-caps;">Detonation</span>:

- Generate a keypair to use for OIDC
- Upload OIDC discovery document and JWKS to the storage account
- Add a Federated Identity Credential (FIC) to the victim Managed Identity that trusts tokens issued by the malicious OIDC provider
- Create a token signed by the attacker's OIDC private key to exchange for a token as the victim Managed Identity
- Exchange the attacker's token for a Microsoft Graph token as the victim Managed Identity using the FIC
- Display the victim Managed Identity's access token to the user

References:

- https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
- https://github.com/azurekid/blackcat/pull/84/changes
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview
- https://hackingthe.cloud/aws/post_exploitation/iam_rogue_oidc_identity_provider/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.persistence.backdoor-managed-identity-fic
```
## Detection


Using [Azure Activity Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log) with the operation name <code>Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write</code>.

Sample Azure Activity Log event to monitor:

```json hl_lines="2 10"
{
    "operationName": {
        "value": "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write",
        "localizedValue": "Add or update Federated Identity Credential"
    },
    "properties": {
        "statusCode": "Created",
        "serviceRequestId": null,
        "eventCategory": "Administrative",
        "entity": "/subscriptions/[SUBSCRIPTION-ID]/stratus-fic-mi-3qbu/providers/Microsoft.ManagedIdentity/userAssignedIdentities/stratus-victim-mi-3qbu/federatedIdentityCredentials/stratus-red-team-oidc-fic",
        "message": "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write",
        "hierarchy": "[REMOVED]"
    }
}
```


