//go:build !azure && !allproviders

package providers

import (
	"github.com/google/uuid"
	"log"
)

type AzureProvider struct{}

func NewAzureProvider(uuid uuid.UUID) *AzureProvider {
	log.Fatal("Azure provider is not compiled in this build. Rebuild with -tags azure or -tags allproviders")
	return nil
}

func (m *AzureProvider) IsAuthenticatedAgainstAzure() bool {
	log.Fatal("Azure provider is not compiled in this build")
	return false
}
