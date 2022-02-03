package providers

import (
	"context"
	"github.com/datadog/stratus-red-team/internal/utils"
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
	KubeconfigDefaultDir  = ".kube"
	KubeconfigDefaultFile = "config"
	StratusK8sNamespace   = "stratus-red-team"
)

type K8sProvider struct {
	k8sClient *kubernetes.Clientset
}

var (
	k8sProvider    K8sProvider
	kubeConfigPath string
)

func K8s() *K8sProvider {
	return &k8sProvider
}

// GetKubeConfigPath returns the path of the kubeconfig, looking at environment variables, and then
// the home directory
func GetKubeConfigPath() string {
	if kubeConfigPath != "" {
		return kubeConfigPath
	}

	// Set to default directory if environment variable is not set, ignore if file doesn't exist
	// to default to in-cluster client config
	if kubeConfigPath = os.Getenv("KUBECONFIG"); kubeConfigPath == "" {
		path := filepath.Join(homedir.HomeDir(), KubeconfigDefaultDir, KubeconfigDefaultFile)
		if utils.FileExists(path) {
			kubeConfigPath = path
		}
	}

	return kubeConfigPath
}

// GetClient is used to authenticate with Kubernetes and build the client from a kubeconfig
func (m *K8sProvider) GetClient() *kubernetes.Clientset {
	kubeconfig := GetKubeConfigPath()

	// Will default to an in-cluster client config if kubeconfig path is not set
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
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
	m.GetClient()

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
