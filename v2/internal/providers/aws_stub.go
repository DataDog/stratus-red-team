//go:build !aws && !allproviders

package providers

import (
	"github.com/google/uuid"
	"log"
)

type AWSProvider struct{}

func NewAWSProvider(uuid uuid.UUID) *AWSProvider {
	log.Fatal("AWS provider is not compiled in this build. Rebuild with -tags aws or -tags allproviders")
	return nil
}

func (m *AWSProvider) IsAuthenticatedAgainstAWS() bool {
	log.Fatal("AWS provider is not compiled in this build")
	return false
}
