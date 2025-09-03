---
title: Dump All Secrets
---

# Dump All Secrets


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Kubernetes

## Mappings

- MITRE ATT&CK
    - Credential Access



## Description


Dumps all Secrets from a Kubernetes cluster. 
This allow an attacker with the right permissions to trivially access all secrets in the cluster.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>: 

- Dump secrets using the **LIST /api/v1/secrets** API
- This returns all secrets in the K8s clusters, no matter their namespace

References:

- https://darkbit.io/blog/the-power-of-kubernetes-rbac-list


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.credential-access.dump-secrets
```
## Detection


Using Kubernetes API server audit logs. In particular, look for **list secrets** requests that are not performed
for a specific namespace (i.e., that apply to all namespaces).

Sample event (shortened):

```json
{
  "apiVersion": "audit.k8s.io/v1",
  "stage": "ResponseComplete",
  "kind": "Event",
  "level": "Metadata",
  "requestURI": "/api/v1/secrets?limit=500",
  "attributes": {
    "objectRef": {
      "resource": "secrets",
      "apiVersion": "v1"
    },
    "http": {
      "url_details": {
        "path": "/api/v1/secrets",
        "queryString": {
          "limit": "500"
        }
      },
      "method": "list"
    }
  }
}
```

Some built-in Kubernetes components might need to be excluded from such a detection:

- namespace-controller
- kube-state-metrics
- apiserver


