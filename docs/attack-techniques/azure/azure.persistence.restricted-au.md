---
title: Restricted Backdoor Account Through Restricted Management AU
---

# Restricted Backdoor Account Through Restricted Management AU

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique may take 5+ minutes to clean up">slow</span> 

Platform: Azure

## MITRE ATT&CK Tactics

- Persistence

## Description

Create a [restricted management Administrative Unit (AU)](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management), and place a backdoor account in it to simulate a protected attacker-controlled user.

Warm-up:

- Create Entra ID user (Backdoor)
- Create restricted management AU

Detonation:

- Add Backdoor user to AU

References:

- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.persistence.restricted-au
```

## Detection

Identify the following <code>activityDisplayName</code> events in Entra ID Audit logs.

For <code>Service: Core Directory</code>,<code>Category: AdministrativeUnit</code>:
Add administrative unit
Add member to restricted management administrative unit

Consider detection of additional Administrative Unit activities and scoped role assignments in the following Microsoft article:
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities