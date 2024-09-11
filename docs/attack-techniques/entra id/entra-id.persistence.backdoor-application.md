---
title: Backdoor Entra ID application
---

# Backdoor Entra ID application




Platform: Entra ID

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Backdoors an existing Entra ID application by creating a new password credential on the app registration.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Entra ID application
- Assign it the <code>Directory Readers</code> role at the tenant level (for illustration purposes)

<span style="font-variant: small-caps;">Detonation</span>:

- Backdoor the Entra ID application by creating a new password credential

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


