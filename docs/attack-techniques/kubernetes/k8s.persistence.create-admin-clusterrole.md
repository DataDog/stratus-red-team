---
title: Create Admin ClusterRole
---

# Create Admin ClusterRole




Platform: Kubernetes

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Creates a Service Account bound to a cluster administrator role.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>: 

- Create a Cluster Role with administrative permissions
- Create a Service Account (in the kube-system namespace)
- Create a Cluster Role Binding
- Retrieve the long-lived service account token, stored by K8s in a secret


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.persistence.create-admin-clusterrole
```
