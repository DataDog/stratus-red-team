//go:build !entraid && !allproviders

package providers

import (
	"github.com/google/uuid"
	"log"
)

type EntraIdProvider struct{}

func NewEntraIdProvider(uuid uuid.UUID) *EntraIdProvider {
	log.Fatal("Entra ID provider is not compiled in this build. Rebuild with -tags entraid or -tags allproviders")
	return nil
}

func (m *EntraIdProvider) IsAuthenticatedAgainstEntraId() bool {
	log.Fatal("Entra ID provider is not compiled in this build")
	return false
}
