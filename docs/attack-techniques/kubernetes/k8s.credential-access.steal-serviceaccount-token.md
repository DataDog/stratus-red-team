---
title: Steal Pod Service Account Token
---

# Steal Pod Service Account Token


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Kubernetes

## Mappings

- MITRE ATT&CK
    - Credential Access



## Description


Steals a service account token from a running pod, by executing a command in the pod and reading /var/run/secrets/kubernetes.io/serviceaccount/token

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create the Stratus Red Team namespace
- Create a Service Account
- Create a Pod running under this service account

<span style="font-variant: small-caps;">Detonation</span>: 

- Execute <code>cat /var/run/secrets/kubernetes.io/serviceaccount/token</code> into the pod to steal its service account token


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.credential-access.steal-serviceaccount-token
```
## Detection


Using Kubernetes API server audit logs, looking for execution events.

Sample event (shortened):

```json hl_lines="3 4 11 12 15"
{
	"objectRef": {
		"resource": "pods",
		"subresource": "exec",
		"name": "stratus-red-team-sample-pod",
	},
	"http": {
		"url_details": {
			"path": "/api/v1/namespaces/stratus-red-team-ubdaslyp/pods/stratus-red-team-sample-pod/exec",
			"queryString": {
				"command": "%2Fvar%2Frun%2Fsecrets%2Fkubernetes.io%2Fserviceaccount%2Ftoken",
				"stdout": "true"
			}
		},
		"method": "create"
	},
	"stage": "ResponseStarted",
	"kind": "Event",
	"level": "RequestResponse",
	"requestURI": "/api/v1/namespaces/stratus-red-team-ubdaslyp/pods/stratus-red-team-sample-pod/exec?command=cat&command=%2Fvar%2Frun%2Fsecrets%2Fkubernetes.io%2Fserviceaccount%2Ftoken&stdout=true",
}
```


