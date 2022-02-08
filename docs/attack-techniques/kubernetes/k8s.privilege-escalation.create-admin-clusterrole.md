---
title: Create Admin ClusterRole
---

# Create Admin ClusterRole




Platform: kubernetes

## MITRE ATT&CK Tactics


- Privilege Escalation

## Description


Creates a Service Account bound to a cluster administrator role.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>: 

- Create a Cluster Role with administrative permissions
- Create a Service Account (in the kube-system namespace)
- Create a Cluster Role Binding
- Create a service account token, simulating an attacker stealing a service account token for the newly created admin role


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.privilege-escalation.create-admin-clusterrole
```