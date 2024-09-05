---
title: Scoped Role Assignment Through HiddenMembership AU
---

# Scoped Role Assignment Through HiddenMembership AU

Platform: Azure

## MITRE ATT&CK Tactics

- Persistence

## Description

Create a HiddenMembership [Administrative Unit (AU)](https://learn.microsoft.com/en-us/graph/api/resources/administrativeunit?view=graph-rest-1.0), and a scoped role assignment over this AU to simulate hidden assigned permissions.

Warm-up:

- Create Target Entra ID user
- Initialize Privileged Administration Administrator role

Detonation:

- Create HiddenMembership AU
- Create Backdoor Entra ID user
- Add Target user to AU
- Assign Backdoor user Privileged Administration Administrator over AU

References:

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.persistence.hidden-au
```

## Detection

Identify the following <code>activityDisplayName</code> events in Entra ID Audit logs.

For <code>Service: Core Directory</code>,<code>Category: AdministrativeUnit</code>:
Add administrative unit
Add member to administrative unit

For <code>Service: Core Directory</code>,<code>Category: RoleManagement</code>:
Add scoped member to role

Consider detection of additional Administrative Unit activities and scoped role assignments in the following Microsoft article:
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities