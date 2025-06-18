---
title: Backdoor Entra ID application
---

# Backdoor Entra ID application




Platform: Entra ID

## Mappings

- MITRE ATT&CK
    - Persistence
  - Privilege Escalation



## Description


Backdoors an existing Entra ID application by creating a new password credential.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Entra ID application and associated service principal
- Assign it the <code>Directory Readers</code> role at the tenant level (for illustration purposes)

<span style="font-variant: small-caps;">Detonation</span>:

- Backdoor the Entra ID application by creating a new password credential

Notes: The warm-up mimics what happens when you create an App Registration through the Azure portal. 
When you use the Azure portal, creating an App Registration automatically creates an associated service principal. 
When using the Microsoft Graph API, the service principal needs to be created separately. 

References:

- https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
- https://www.inversecos.com/2021/10/how-to-backdoor-azure-applications-and.html
- https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5
- https://redfoxsec.com/blog/azure-privilege-escalation-via-service-principal/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate entra-id.persistence.backdoor-application
```
## Detection


Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the activity type <code>Update application – Certificates and secrets management</code>.


