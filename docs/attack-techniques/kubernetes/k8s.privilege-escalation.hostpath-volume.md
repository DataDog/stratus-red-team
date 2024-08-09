---
title: Container breakout via hostPath volume mount
---

# Container breakout via hostPath volume mount




Platform: Kubernetes

## MITRE ATT&CK Tactics


- Privilege Escalation

## Description


Creates a Pod with the entire node root filesystem as a hostPath volume mount

References:

- https://attack.mitre.org/techniques/T1611/
- https://www.youtube.com/watch?v=gtaaONq-XGY

<span style="font-variant: small-caps;">Warm-up</span>: 

- Creates the Stratus Red Team namespace

<span style="font-variant: small-caps;">Detonation</span>: 

- Create a privileged busybox pod with the node root filesystem mounted at "/host" 
	that reads "/etc/passwd" from the host filesystem


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.privilege-escalation.hostpath-volume
```
