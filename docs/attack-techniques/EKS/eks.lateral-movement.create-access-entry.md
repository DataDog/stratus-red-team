---
title: Create Admin EKS Access Entry
---

# Create Admin EKS Access Entry




Platform: EKS

## MITRE ATT&CK Tactics


- Lateral Movement

## Description


Uses the EKS Cluster Access Management to assign cluster administrator privileges to an IAM role. This allows the role to perform any action inside the Kubernetes cluster.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM role

<span style="font-variant: small-caps;">Detonation</span>:

- Create an access entry for the IAM role
- Associate the access entry with the AmazonEKSClusterAdminPolicy access policy

References: 

- https://securitylabs.datadoghq.com/articles/eks-cluster-access-management-deep-dive/
- https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate eks.lateral-movement.create-access-entry
```
## Detection


You can use the following CloudTrail events to identify when someone grants access to your EKS cluster:

- **CreateAccessEntry**, when someone creates an access entry for a principal (meaning it's the first this principal is granted privileges in the cluster)':

```json
{
	"eventSource": "eks.amazonaws.com",
	"eventName": "CreateAccessEntry",
	"requestParameters": {
		"name": "eks-cluster",
		"principalArn": "arn:aws:iam::012345678901:role/stratus-red-team-eks-create-access-entry-role"
	},
	"responseElements": {
		"accessEntry": {
			"clusterName": "eks-cluster",
			"type": "STANDARD",
			"principalArn": "arn:aws:iam::012345678901:role/stratus-red-team-eks-create-access-entry-role",
		}
	}
}
```


- **AssociateAccessPolicy**: when someone assigns an access policy to a principal

```json
{
  "eventSource": "eks.amazonaws.com",
  "eventName": "AssociateAccessPolicy",
  "requestParameters": {
    "policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
    "accessScope": {
      "type": "cluster"
    },
    "name": "eks-cluster",
    "principalArn": "arn%3Aaws%3Aiam%3A%3A012345678901%3Arole%2Fstratus-red-team-eks-create-access-entry-role"
  }
}
```




