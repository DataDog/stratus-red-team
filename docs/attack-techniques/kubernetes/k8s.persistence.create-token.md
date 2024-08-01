---
title: Create Long-Lived Token
---

# Create Long-Lived Token


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Kubernetes

## MITRE ATT&CK Tactics


- Persistence

## Description


Creates a token with a large expiration for a service account. An attacker can create such a long-lived token to easily gain 
persistence on a compromised cluster.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.persistence.create-token
```
## Detection


Using Kubernetes API server audit logs. In particular, look for create service account tokens requests to privileged
service accounts, or service accounts inside the kube-system namespace.

```json
{
  "objectRef": {
    "resource": "serviceaccounts",
    "subresource": "token",
    "name": "clusterrole-aggregation-controller",
    "apiVersion": "v1"
  },
  "http": {
    "url_details": {
      "path": "/api/v1/namespaces/kube-system/serviceaccounts/clusterrole-aggregation-controller/token"
    },
    "method": "create",
    "status_code": 201
  },
  "stage": "ResponseComplete",
  "kind": "Event",
  "level": "Metadata",
  "requestURI": "/api/v1/namespaces/kube-system/serviceaccounts/clusterrole-aggregation-controller/token",
}
```

To reduce false positives, it may be useful to filter out the following attributes:

* User name is <code>system:kube-controller-manager</code>
* User group contains <code>system:nodes</code>

Notes:

* The API server audit log does not contain the requested token lifetime, unless the audit logs level is <code>Request</code> or <code>RequestResponse</code> (which is generally not the case)

* AWS EKS caps the token lifetime to 1 hour, although the behavior is undocumented and not part of Kubernetes itself.




