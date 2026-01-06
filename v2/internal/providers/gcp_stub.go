//go:build !gcp && !allproviders

package providers

import (
	"github.com/google/uuid"
	"log"
)

type GCPProvider struct{}

func NewGCPProvider(uuid uuid.UUID) *GCPProvider {
	log.Fatal("GCP provider is not compiled in this build. Rebuild with -tags gcp or -tags allproviders")
	return nil
}

func (m *GCPProvider) IsAuthenticated() bool {
	log.Fatal("GCP provider is not compiled in this build")
	return false
}
