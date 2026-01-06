//go:build !kubernetes && !allproviders

package providers

import (
	"github.com/google/uuid"
	"log"
)

type K8sProvider struct{}

func NewK8sProvider(uuid uuid.UUID) *K8sProvider {
	log.Fatal("Kubernetes provider is not compiled in this build. Rebuild with -tags kubernetes or -tags allproviders")
	return nil
}

func (m *K8sProvider) IsAuthenticated() bool {
	log.Fatal("Kubernetes provider is not compiled in this build")
	return false
}

func GetKubeConfigPath() string {
	log.Fatal("Kubernetes provider is not compiled in this build")
	return ""
}
