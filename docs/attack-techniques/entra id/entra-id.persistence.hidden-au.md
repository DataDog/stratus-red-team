---
title: Create Hidden Scoped Role Assignment Through HiddenMembership AU
---

# Create Hidden Scoped Role Assignment Through HiddenMembership AU




Platform: Entra ID

## MITRE ATT&CK Tactics


- Persistence

## Description


Creates an [Administrative Unit (AU)](https://learn.microsoft.com/en-us/graph/api/resources/administrativeunit?view=graph-rest-1.0) with hidden membership, and a scoped role assignment over this AU.
This simulates an attacker that TODO.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create Target Entra ID user
- Initialize Privileged Administration Administrator role

<span style="font-variant: small-caps;">Detonation</span>:

- Create HiddenMembership AU
- Create Backdoor Entra ID user
- Add Target user to AU
- Assign Backdoor user Privileged Administration Administrator over AU

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


