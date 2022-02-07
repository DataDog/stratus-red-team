---
title: Run a Privileged Pod
---

# Run a Privileged Pod




Platform: kubernetes

## MITRE ATT&CK Tactics


- Privilege Escalation

## Description


Runs a privileged pod. Privileged pods are equivalent to running as root on the worker node, and can be used for privilege escalation.

Resources:

- https://www.cncf.io/blog/2020/10/16/hack-my-mis-configured-kubernetes-privileged-pods/
- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

<span style="font-variant: small-caps;">Warm-up</span>: 

- Creates the Stratus Red Team namespace

<span style="font-variant: small-caps;">Detonation</span>: 

- Create a privileged busybox pod


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.privilege-escalation.privileged-pod
```