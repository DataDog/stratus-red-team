---
title: Create Hidden Scoped Role Assignment Through HiddenMembership AU
---

# Create Hidden Scoped Role Assignment Through HiddenMembership AU




Platform: Entra ID

## Mappings

- MITRE ATT&CK
    - Persistence



## Description


Creates an [Administrative Unit (AU)](https://learn.microsoft.com/en-us/graph/api/resources/administrativeunit?view=graph-rest-1.0) with hidden membership, and a scoped role assignment over this AU. This simulates an attacker attempting to conceal the scope of a scoped role assignment using hidden AU membership.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create the target (victim) Entra ID user

<span style="font-variant: small-caps;">Detonation</span>:

- Create an administrative unit with hidden membership
- Create a backdoor Entra ID user
- Add the target (victim) user to the administrative unit
- Assign the backdoor user with Privileged Administration Administrator rights over the administrative unit

This simulates an attacker that indirectly persists their access. 
The backdoor user can now perform privileged operations over any user in the administrative unit, which can be used to escalate privileges or maintain access, for instance by resetting the target user's password.

References:

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units



## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate entra-id.persistence.hidden-au
```
## Detection


Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the specific activity types:

For <code>Service: Core Directory</code> and <code>Category: AdministrativeUnit</code>:

- <code>Add administrative unit</code>
- <code>Add member to administrative unit</code>

For <code>Service: Core Directory</code> and <code>Category: RoleManagement</code>:

- <code>Add scoped member to role</code>


