package providers

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	betagraph "github.com/microsoftgraph/msgraph-beta-sdk-go"
	graph "github.com/microsoftgraph/msgraph-sdk-go"
	"log"
)

type EntraIdProvider struct {
	Credentials     azcore.TokenCredential
	ClientOptions   *arm.ClientOptions
	GraphClient     *graph.GraphServiceClient
	BetaGraphClient *betagraph.GraphServiceClient
}

// EntraIdProviderOption configures optional overrides on an EntraIdProvider.
type EntraIdProviderOption func(*EntraIdProvider)

// WithEntraIdCredentials overrides the default credential chain with an
// explicit azcore.TokenCredential.
func WithEntraIdCredentials(cred azcore.TokenCredential) EntraIdProviderOption {
	return func(p *EntraIdProvider) { p.Credentials = cred }
}

func NewEntraIdProvider(correlationId uuid.UUID, opts ...EntraIdProviderOption) *EntraIdProvider {
	p := &EntraIdProvider{}
	for _, opt := range opts {
		opt(p)
	}

	if p.Credentials == nil {
		creds, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			log.Fatalf("failed to pull the result: %v", err)
		}
		p.Credentials = creds
	}

	p.ClientOptions = &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Telemetry: policy.TelemetryOptions{ApplicationID: correlationId.String(), Disabled: false},
		},
	}

	graphClient, err := graph.NewGraphServiceClientWithCredentials(p.Credentials, nil)
	if err != nil {
		log.Fatalf("could initialize Entra ID Graph client: %v", err)
	}
	p.GraphClient = graphClient

	betaGraphClient, err := betagraph.NewGraphServiceClientWithCredentials(p.Credentials, nil)
	if err != nil {
		log.Fatalf("could initialize Entra ID Beta Graph client: %v", err)
	}
	p.BetaGraphClient = betaGraphClient

	return p
}

func (m *EntraIdProvider) GetGraphClient() *graph.GraphServiceClient {
	return m.GraphClient
}

func (m *EntraIdProvider) GetBetaGraphClient() *betagraph.GraphServiceClient {
	return m.BetaGraphClient
}

func (m *EntraIdProvider) GetTenantId() (string, error) {
	organization, err := m.GetGraphClient().Organization().Get(context.Background(), nil)
	if err != nil {
		return "", err
	}

	return *organization.GetValue()[0].GetId(), nil
}

func (m *EntraIdProvider) IsAuthenticatedAgainstEntraId() bool {
	_, err := m.Credentials.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	return err == nil
}
