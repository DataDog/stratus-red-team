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
	Credentials     *azidentity.DefaultAzureCredential
	ClientOptions   *arm.ClientOptions
	GraphClient     *graph.GraphServiceClient
	BetaGraphClient *betagraph.GraphServiceClient
}

func NewEntraIdProvider(uuid uuid.UUID) *EntraIdProvider {
	creds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}

	var DefaultClientOptions = arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Telemetry: policy.TelemetryOptions{ApplicationID: uuid.String(), Disabled: false},
		},
	}

	graphClient, err := graph.NewGraphServiceClientWithCredentials(creds, nil)
	if err != nil {
		log.Fatalf("could initialize Entra ID Graph client: %v", err)
	}

	betaGraphClient, err := betagraph.NewGraphServiceClientWithCredentials(creds, nil)
	if err != nil {
		log.Fatalf("could initialize Entra ID Beta Graph client: %v", err)
	}

	return &EntraIdProvider{
		Credentials:     creds,
		ClientOptions:   &DefaultClientOptions,
		GraphClient:     graphClient,
		BetaGraphClient: betaGraphClient,
	}
}

func (m *EntraIdProvider) GetGraphClient() *graph.GraphServiceClient {
	return m.GraphClient
}

func (m *EntraIdProvider) GetBetaGraphClient() *betagraph.GraphServiceClient {
	return m.BetaGraphClient
}

func (m *EntraIdProvider) IsAuthenticatedAgainstEntraId() bool {
	_, err := m.Credentials.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	return err == nil
}
