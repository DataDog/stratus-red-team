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
## Detection


Using Kubernetes API server audit logs, looking for pod creation events with <code>requestObject.spec.containers[*].securityContext.privileged</code>
set to <code>true</code>.

Sample event (shortened):

```json hl_lines="11 19 26"
{
	"objectRef": {
		"resource": "pods",
		"name": "k8s.privilege-escalation.privileged-pod",
		"apiVersion": "v1"
	},
	"http": {
		"url_details": {
			"path": "/api/v1/namespaces/stratus-red-team-umusjhhg/pods"
		},
		"method": "create",
		"status_code": 201,
	},
	"stage": "ResponseComplete",
	"kind": "Event",
	"level": "RequestResponse",
	"requestURI": "/api/v1/namespaces/stratus-red-team-umusjhhg/pods",
	"requestObject": {
		"kind": "Pod",
		"spec": {
			"containers": [{
				"image": "busybox:stable",
				"args": ["while true; do sleep 3600; done"],
				"command": ["sh", "-c"],
				"securityContext": {
					"privileged": true
				}
			}]
		},
		"apiVersion": "v1",
		"metadata": {
			"namespace": "stratus-red-team-umusjhhg",
			"name": "k8s.privilege-escalation.privileged-pod"
		}
	}
}
```

