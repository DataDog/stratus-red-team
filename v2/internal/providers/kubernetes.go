package providers

import (
	"context"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"os"
	"path/filepath"

	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/config"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
	"github.com/google/uuid"
	authv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	KubeconfigDefaultPath = ".kube/config"
)

type K8sProvider struct {
	k8sClient           *kubernetes.Clientset
	RestConfig          *rest.Config
	UniqueCorrelationId uuid.UUID // unique value injected in the user-agent, to differentiate Stratus Red Team executions
}

var (
	kubeConfigPath            string
	kubeConfigPathWasResolved bool
)

// K8sProviderOption configures optional overrides on a K8sProvider.
type K8sProviderOption func(*K8sProvider)

// WithK8sRestConfig overrides the default kubeconfig / in-cluster resolution
// with an explicit rest.Config.
func WithK8sRestConfig(cfg *rest.Config) K8sProviderOption {
	return func(p *K8sProvider) { p.RestConfig = cfg }
}

func NewK8sProvider(correlationId uuid.UUID, opts ...K8sProviderOption) *K8sProvider {
	p := &K8sProvider{UniqueCorrelationId: correlationId}
	for _, opt := range opts {
		opt(p)
	}

	if p.RestConfig == nil {
		restConfig, err := buildKubeRestConfig()
		if err != nil {
			log.Fatalf("unable to build kube config: %v", err)
		}
		p.RestConfig = restConfig
	}

	p.RestConfig.UserAgent = useragent.GetStratusUserAgentForUUID(correlationId)
	k8sClient, err := kubernetes.NewForConfig(p.RestConfig)
	if err != nil {
		log.Fatalf("unable to create kube client: %v", err)
	}
	p.k8sClient = k8sClient

	return p
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

	// Otherwise, return an empty string.
	// This causes the loading rules used by buildKubeRestConfig to fall back to
	// in-cluster auth.
	return ""
}

// buildKubeRestConfig resolves the Kubernetes REST configuration the same way
// kubectl does. It honors the KUBECONFIG environment variable - including when
// it holds several ':'-separated paths, which are then merged together - and
// otherwise falls back to $HOME/.kube/config, then to in-cluster credentials.
// The current context is resolved across the merged files.
func buildKubeRestConfig() (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

// GetClient is used to authenticate with Kubernetes and build the client from a kubeconfig
func (m *K8sProvider) GetClient() *kubernetes.Clientset {
	return m.k8sClient
}

func (m *K8sProvider) GetRestConfig() *rest.Config {
	return m.RestConfig
}

func (m *K8sProvider) IsAuthenticated() bool {
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

// ApplyPodConfig applies configuration from the config file to a pod spec. Modifies the pod in place.
func (m *K8sProvider) ApplyPodConfig(techniqueID string, pod *v1.Pod) {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Println("Warning: unable to load config, pod configuration will not be applied: " + err.Error())
		return
	}
	if cfg == nil {
		return
	}

	vars := config.SubstitutionVars{CorrelationID: m.UniqueCorrelationId.String()}
	techniqueConfig := cfg.GetKubernetesConfig().GetTechniquePodConfig(techniqueID, vars)
	techniqueConfig.ApplyToPod(pod)
}
