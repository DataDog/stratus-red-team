---
title: Create Client Certificate Credential
---

# Create Client Certificate Credential


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Kubernetes

## MITRE ATT&CK Tactics


- Persistence

## Description


Creates a client certificate for a privileged user. This client certificate can be used to authenticate to the cluster.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>:

- Create a certificate signing request (CSR)
- Wait for the CSR to be picked up and return a certificate
- Print the client-side certificate and private key

Note: This attack technique does not succeed on AWS EKS. Due to apparent [undocumented behavior](https://github.com/aws/containers-roadmap/issues/1604), 
the managed EKS control plane does not issue a certificate for the certificate signing request (CSR), even when approved. However, it is still relevant
to simulate attacker behavior.

Note: The certificate is issued to <code>system:kube-controller-manager</code> because it exists in most clusters, and already has a ClusterRoleBinding to <code>ClusterRole/system:kube-controller-manager</code>
which includes privileged permissions, such as access all secrets of the cluster and create tokens for any service account.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.persistence.create-client-certificate
```
## Detection


Using Kubernetes API server audit logs. In particular, look for creation and approval of CSR objects, which do 
not relate to standard cluster operation (e.g. Kubelet certificate issuance).


