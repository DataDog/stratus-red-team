package providers

import (
	"context"
	"log"
	"path/filepath"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	KubeconfigDefaultPath = ".kube/config"
	StratusK8sNamespace   = "stratus-red-team"
)

type K8sProvider struct {
	k8sClient *kubernetes.Clientset
}

var k8sProvider = K8sProvider{}

func K8s() *K8sProvider {
	return &k8sProvider
}

// GetClient is used to authenticate with Kubernetes and build the client from a kubeconfig
func (m *K8sProvider) GetClient(kubeConfigPath string) *kubernetes.Clientset {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		log.Fatalf("unable to build kube config: %v", err)
	}
	m.k8sClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("unable to create kube client: %v", err)
	}
	return m.k8sClient
}

func (m *K8sProvider) IsAuthenticated() bool {
	// Use ~/.kube/config as default kubeconfig path
	m.GetClient(filepath.Join(homedir.HomeDir(), KubeconfigDefaultPath))

	// Check to see if the user can create pods as a check
	// for proper permissions on the cluster
	var self = authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: StratusK8sNamespace,
				Verb:      "create",
				Resource:  "pods",
			},
		},
	}
	auth, err := m.k8sClient.AuthorizationV1().SelfSubjectAccessReviews().Create(
		context.Background(),
		&self,
		metav1.CreateOptions{},
	)
	return err == nil || auth.Status.Allowed
}
