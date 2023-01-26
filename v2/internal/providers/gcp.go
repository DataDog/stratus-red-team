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

type GCPProvider struct {
	UniqueCorrelationId uuid.UUID
	ProjectId           string
}

func NewGCPProvider(uuid uuid.UUID) *GCPProvider {
	return &GCPProvider{
		UniqueCorrelationId: uuid,
		ProjectId:           getProjectId(),
	}
}

func (m *GCPProvider) Options() option.ClientOption {
	return option.WithUserAgent(GetStratusUserAgentForUUID(m.UniqueCorrelationId))
}

func (m *GCPProvider) IsAuthenticated() bool {
	_, err := iam.NewService(context.Background())
	return err == nil && m.ProjectId != ""
}

func (m *GCPProvider) GetProjectId() string {
	return m.ProjectId
}
