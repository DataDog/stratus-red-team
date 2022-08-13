package providers

import (
	"context"
	"os"

	"github.com/google/uuid"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// TF and GCP defines multiple environment variables for this
// https://registry.terraform.io/providers/hashicorp/google/latest/docs/guides/provider_reference#full-reference

func getProjectId() string {
	gcloudProjEnvVars := []string{
		"GOOGLE_PROJECT",
		"GOOGLE_CLOUD_PROJECT",
		"GCLOUD_PROJECT",
		"CLOUDSDK_CORE_PROJECT",
	}
	for _, key := range gcloudProjEnvVars {
		if projectId, hasEnvVariable := os.LookupEnv(key); hasEnvVariable {
			return projectId
		}
	}
	return ""
}

type GcpProvider struct {
	UniqueCorrelationId uuid.UUID
	ProjectId           string
}

var gcpProvider = GcpProvider{
	UniqueCorrelationId: UniqueExecutionId,
	ProjectId:           getProjectId(),
}

func GCP() *GcpProvider {
	return &gcpProvider
}

func (m *GcpProvider) Options() option.ClientOption {
	return option.WithUserAgent(GetStratusUserAgent())
}

func (m *GcpProvider) IsAuthenticated() bool {
	ctx := context.Background()
	_, err := iam.NewService(ctx)
	return err == nil && m.ProjectId != ""
}

func (m *GcpProvider) GetProjectId() string {
	return m.ProjectId
}
