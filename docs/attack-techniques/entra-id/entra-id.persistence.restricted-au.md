---
title: Create Sticky Backdoor Account Through Restricted Management AU
---

# Create Sticky Backdoor Account Through Restricted Management AU




Platform: Entra ID

## MITRE ATT&CK Tactics


- Persistence

## Description


Create a [restricted management Administrative Unit (AU)](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management), and place a backdoor account in it to simulate a protected attacker-controlled user.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create Entra ID user (Backdoor)

<span style="font-variant: small-caps;">Detonation</span>:

- Create restricted management AU
- Add Backdoor user to AU

References:

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management



## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate entra-id.persistence.restricted-au
```
## Detection


Identify the following <code>activityDisplayName</code> events in Entra ID Audit logs.

For <code>Service: Core Directory</code>,<code>Category: AdministrativeUnit</code>:
Add administrative unit
Add member to restricted management administrative unit

Consider detection of additional Administrative Unit activities and scoped role assignments in the following Microsoft article:
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities


