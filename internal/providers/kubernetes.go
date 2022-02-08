package providers

import (
	"context"
	"github.com/datadog/stratus-red-team/internal/utils"
	"k8s.io/client-go/rest"
	"log"
	"os"
	"path/filepath"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	KubeconfigDefaultPath = ".kube/config"
)

type K8sProvider struct {
	k8sClient  *kubernetes.Clientset
	RestConfig *rest.Config
}

var (
	k8sProvider               K8sProvider
	kubeConfigPath            string
	kubeConfigPathWasResolved bool
)

func K8s() *K8sProvider {
	return &k8sProvider
}

// GetKubeConfigPath returns the path of the kubeconfig, with the following priority:
// 1. KUBECONFIG environment variable
// 2. $HOME/.kube/config
func GetKubeConfigPath() string {
	if !kubeConfigPathWasResolved {
		kubeConfigPath = getKubeConfigPath()
		kubeConfigPathWasResolved = true // Note: we can't use an empty string since it's a possible return value of getKubeConfigPath
	}

	return kubeConfigPath
}

// unexported function with the main logic
func getKubeConfigPath() string {
	// if KUBECONFIG is set, use it
	if kubeConfigEnvPath := os.Getenv("KUBECONFIG"); kubeConfigEnvPath != "" {
		return kubeConfigEnvPath
	}

	// Otherwise, use $HOME/.kube/config if it exists
	if kubeConfigFilePath := filepath.Join(homedir.HomeDir(), KubeconfigDefaultPath); utils.FileExists(kubeConfigFilePath) {
		return kubeConfigFilePath
	}

	// Otherwise, return an empty string
	// This will cause `clientcmd.BuildConfigFromFlags` called in `GetClient` will try to use
	// in-cluster auth
	// c.f. https://pkg.go.dev/k8s.io/client-go/tools/clientcmd#BuildConfigFromFlags
	return ""
}

// GetClient is used to authenticate with Kubernetes and build the client from a kubeconfig
func (m *K8sProvider) GetClient() *kubernetes.Clientset {
	kubeconfig := GetKubeConfigPath()

	// Will default to an in-cluster client config if kubeconfig path is not set
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("unable to build kube config: %v", err)
	}
	m.RestConfig = config
	m.RestConfig.UserAgent = StratusUserAgent
	m.k8sClient, err = kubernetes.NewForConfig(m.RestConfig)
	if err != nil {
		log.Fatalf("unable to create kube client: %v", err)
	}
	return m.k8sClient
}

func (m *K8sProvider) GetRestConfig() *rest.Config {
	return m.RestConfig
}

func (m *K8sProvider) IsAuthenticated() bool {
	m.GetClient()

	// We assume if the current user can do 'kubectl list pods' in the default namespace, they are authenticated
	// Note: we do not perform authorization checks
	var self = authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Verb:     "list",
				Resource: "pods",
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
