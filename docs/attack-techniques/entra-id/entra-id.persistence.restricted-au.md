---
title: Create Sticky Backdoor User Through Restricted Management AU
---

# Create Sticky Backdoor User Through Restricted Management AU




Platform: Entra ID

## MITRE ATT&CK Tactics


- Persistence

## Description


Creates a [restricted management Administrative Unit (AU)](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management), and place a backdoor account in it to simulate a protected attacker-controlled user.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Entra ID backdoor user

<span style="font-variant: small-caps;">Detonation</span>:

- Create restricted management Administrative Unit
- Add the backdoor user to the Administrative Unit

References:

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management

Note: When cleaning up the technique, you might have to wait a few minutes for the user status to update before retrying the cleanup. This is a limitation of Entra ID.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate entra-id.persistence.restricted-au
```
## Detection


Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the specific activity types:

- <code>Add administrative unit</code>
- <code>Add member to restricted management administrative unit</code>


