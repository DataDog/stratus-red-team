---
title: Privilege escalation through node/proxy permissions
---

# Privilege escalation through node/proxy permissions


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Kubernetes

## MITRE ATT&CK Tactics


- Privilege Escalation

## Description


Uses the node proxy API to proxy a Kubelet request through a worker node. This is a vector of privilege escalation, allowing
any principal with the `nodes/proxy` permission to escalate their privilege to cluster administrator, 
bypassing at the same time admission control checks and logging of the API server.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a namespace
- Create a service account in this namespace
- Create a cluster role with `nodes/proxy` permissions 
- Bind the cluster role to the service account

<span style="font-variant: small-caps;">Detonation</span>:

- Retrieve a token for the service account with `nodes/proxy` permissions creating during warm-up
- Use the node proxy API to proxy a benign request to the Kubelet through the worker node

References:

- https://blog.aquasec.com/privilege-escalation-kubernetes-rbac
- https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.22/#-strong-proxy-operations-node-v1-core-strong-



## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.privilege-escalation.nodes-proxy
```
## Detection


Using Kubernetes API server audit logs, you can identify when the nodes proxy API is used.

Sample event (shortened):

```json hl_lines="3 4"
{
  "objectRef": {
    "resource": "nodes",
    "subresource": "proxy",
    "name": "ip-192-168-34-255.eu-west-1.compute.internal",
    "apiVersion": "v1"
  },
  "http": {
    "url_details": {
      "path": "/api/v1/nodes/ip-192-168-34-255.eu-west-1.compute.internal/proxy/runningpods/"
    },
    "method": "get",
    "status_code": 200,
    "status_category": "OK"
  },
  "kind": "Event",
  "level": "Request",
  "requestURI": "/api/v1/nodes/ip-192-168-34-255.eu-west-1.compute.internal/proxy/runningpods/",
}
```

Under normal operating conditions, it's not expected that this API is used frequently. 
Consequently, alerting on `objectRef.resource == "nodes" && objectRef.subresource == "proxy"` should yield minimal false positives.

Additionally, looking at the Kubelet API path that was proxied can help identify malicious activity (/runningpods in this example).
See [kubeletctl](https://github.com/cyberark/kubeletctl/blob/master/pkg/api/constants.go) for an unofficial list of Kubelet API endpoints.


