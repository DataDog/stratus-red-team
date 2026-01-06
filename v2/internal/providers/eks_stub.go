//go:build !eks && !allproviders

package providers

import (
	"github.com/google/uuid"
	"log"
)

type EKSProvider struct{}

func NewEKSProvider(uuid uuid.UUID) *EKSProvider {
	log.Fatal("EKS provider is not compiled in this build. Rebuild with -tags eks or -tags allproviders")
	return nil
}

func (m *EKSProvider) IsAuthenticatedAgainstEKS() bool {
	log.Fatal("EKS provider is not compiled in this build")
	return false
}
