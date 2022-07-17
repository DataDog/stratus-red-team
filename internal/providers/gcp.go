package providers

import (
	"context"
	"log"
	"os"

	"github.com/google/uuid"
	"google.golang.org/api/iam/v1"
)

// TF and GCP defines multiple environment variables for this
// https://registry.terraform.io/providers/hashicorp/google/latest/docs/guides/provider_reference#full-reference

func IsProjectEnvVarSet() bool {
	gcloudProjEnvVars := []string{
		"GOOGLE_PROJECT",
		"GOOGLE_CLOUD_PROJECT",
		"GCLOUD_PROJECT",
		"CLOUDSDK_CORE_PROJECT",
	}

	for _, key := range gcloudProjEnvVars {
		if len(os.Getenv(key)) != 0 {
			log.Println(key + " var set!")
			return true
		}
	}
	return false
}

type GcpProvider struct {
	UniqueCorrelationId uuid.UUID
}

var gcpProvider = GcpProvider{
	UniqueCorrelationId: UniqueExecutionId,
}

func GCP() *GcpProvider {
	return &gcpProvider
}

//func Gcp() {}

//func GetClientParams(){}

func (m *GcpProvider) IsAuthenticated() bool {
	ctx := context.Background()
	_, err := iam.NewService(ctx)
	if err != nil {
		log.Println("Authentication Error:" + err.Error())
		return false
	}
	if !IsProjectEnvVarSet() {
		return false
	}

	return true
}
