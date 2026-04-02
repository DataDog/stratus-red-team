---
title: Backdoor Entra ID application with Federated Identity Credential (FIC)
---

# Backdoor Entra ID application with Federated Identity Credential (FIC)




Platform: Entra ID

## Mappings

- MITRE ATT&CK
    - Persistence
  - Privilege Escalation



## Description


Backdoors an existing Entra ID application by creating a new Federated Identity Credential (FIC) that trusts an attacker-controlled OIDC provider.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a victim Entra ID application and associated service principal
- Assign it the <code>Directory Readers</code> role at the tenant level (for illustration purposes)
- Create an Azure Storage account to host the attacker-controlled OIDC provider metadata

<span style="font-variant: small-caps;">Detonation</span>:

- Generate a keypair to use for OIDC
- Upload OIDC discovery document and JWKS to the storage account
- Add a Federated Identity Credential (FIC) to the victim application that trusts tokens issued by the malicious OIDC provider
- Create a token signed by the attacker's OIDC private key to exchange for a token as the victim application
- Exchange the attacker's token for a Microsoft Graph token as the victim application using the FIC
- Display the victim application's access token to the user

References:

- https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
- https://github.com/azurekid/blackcat/pull/84/changes
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview
- https://hackingthe.cloud/aws/post_exploitation/iam_rogue_oidc_identity_provider/



## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate entra-id.persistence.backdoor-application-fic
```
## Detection


Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the activity type <code>Update application</code>, where <code>ModifiedProperties</code> contains a <code>displayName</code> of <code>Included Updated Properties</code> and a value of <code>FederatedIdentityCredentials</code>.


