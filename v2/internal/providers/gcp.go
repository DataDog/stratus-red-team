package providers

import (
	"context"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
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

// GCPProviderOption configures optional overrides on a GCPProvider.
type GCPProviderOption func(*GCPProvider)

// WithGCPProjectID overrides the project ID instead of reading it from
// environment variables.
func WithGCPProjectID(projectId string) GCPProviderOption {
	return func(p *GCPProvider) { p.ProjectId = projectId }
}

func NewGCPProvider(correlationId uuid.UUID, opts ...GCPProviderOption) *GCPProvider {
	p := &GCPProvider{
		UniqueCorrelationId: correlationId,
		ProjectId:           getProjectId(),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (m *GCPProvider) Options() option.ClientOption {
	return option.WithUserAgent(useragent.GetStratusUserAgentForUUID(m.UniqueCorrelationId))
}

func (m *GCPProvider) IsAuthenticated() bool {
	_, err := iam.NewService(context.Background())
	return err == nil && m.ProjectId != ""
}

func (m *GCPProvider) GetProjectId() string {
	return m.ProjectId
}
