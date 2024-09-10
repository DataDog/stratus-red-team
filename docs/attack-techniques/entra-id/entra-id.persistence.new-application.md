---
title: Create Application
---

# Create Application




Platform: Entra ID

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Creates a new Entra ID application to backdoor the tenant.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>:

- Create a new Entra ID application
- Create a password credential for the application
- Create a service principal for the application
- Assign the Global Administrator role to the application
- Print the command to retrieve a Graph API access token

References:

- https://www.microsoft.com/en-us/security/blog/2023/12/12/threat-actors-misuse-oauth-applications-to-automate-financially-driven-attacks/
- https://www.inversecos.com/2021/10/how-to-backdoor-azure-applications-and.html

## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate entra-id.persistence.new-application
```
## Detection


Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the specific activity types:

- <code>Add application</code>
- <code>Update application – Certificates and secrets management</code>
- <code>Add member to role</code>


