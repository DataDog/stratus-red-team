---
title: Backdoor aws-auth EKS ConfigMap
---

# Backdoor aws-auth EKS ConfigMap




Platform: EKS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Backdoors the aws-auth ConfigMap in an EKS cluster to grant access to the cluster to a specific role.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM role

<span style="font-variant: small-caps;">Detonation</span>:

- Add an entry to the aws-auth ConfigMap to grant administrator access to the cluster to the role

References: 

- https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/#authorization-the-aws-auth-configmap-deprecated
- https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate eks.persistence.backdoor-aws-auth-configmap
```
## Detection


Through EKS API Server audit logs, by looking for changes to the aws-auth ConfigMap in the kube-system namespace. Here's what a relevant audit event looks like:

```json
{
  "objectRef": {
    "apiVersion": "v1",
    "resource": "configmaps",
    "name": "aws-auth"
  },
  "requestURI": "/api/v1/namespaces/kube-system/configmaps/aws-auth",
  "requestObject": {
    "metadata": {
      "resourceVersion": "184358280",
      "name": "aws-auth",
      "namespace": "kube-system",
      "creationTimestamp": "2022-07-20T13:13:30Z"
    },
    "apiVersion": "v1",
    "data": {
      "mapRoles": "- groups:\n    - system:masters\n  rolearn: arn:aws:iam::012345678901:role/account-admin\n  username: cluster-admin-{{SessionName}}\n- groups:\n    - system:bootstrappers\n    - system:nodes\n  rolearn: arn:aws:iam::012345678901:role/eksctl-cluser-NodeInstanceRole\n  username: system:node:{{EC2PrivateDNSName}}\n- groups:\n    - system:masters\n  rolearn: arn:aws:iam::012345678901:role/stratus-red-team-eks-backdoor-aws-auth-role\n  username: backdoor\n"
    },
    "kind": "ConfigMap"
  }
}
```


