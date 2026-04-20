package providers

import (
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/google/uuid"
)

const azureSubscriptionIdEnvVarKey = "AZURE_SUBSCRIPTION_ID"

type AzureProvider struct {
	Credentials         azcore.TokenCredential
	ClientOptions       *arm.ClientOptions
	SubscriptionID      string
	UniqueCorrelationId uuid.UUID // unique value injected in the user-agent, to differentiate Stratus Red Team executions
}

// AzureProviderOption configures optional overrides on an AzureProvider.
type AzureProviderOption func(*AzureProvider)

// WithAzureCredentials overrides the default credential chain with an explicit
// azcore.TokenCredential.
func WithAzureCredentials(cred azcore.TokenCredential) AzureProviderOption {
	return func(p *AzureProvider) { p.Credentials = cred }
}

// WithAzureSubscriptionID overrides the subscription ID instead of reading it
// from the AZURE_SUBSCRIPTION_ID environment variable.
func WithAzureSubscriptionID(subscriptionID string) AzureProviderOption {
	return func(p *AzureProvider) { p.SubscriptionID = subscriptionID }
}

func NewAzureProvider(correlationId uuid.UUID, opts ...AzureProviderOption) *AzureProvider {
	p := &AzureProvider{UniqueCorrelationId: correlationId}
	for _, opt := range opts {
		opt(p)
	}

	if p.SubscriptionID == "" {
		p.SubscriptionID = os.Getenv(azureSubscriptionIdEnvVarKey)
		if p.SubscriptionID == "" {
			log.Fatal(azureSubscriptionIdEnvVarKey + " is not set.")
		}
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
	return p
}

func (m *AzureProvider) GetCredentials() azcore.TokenCredential {
	return m.Credentials
}

func (m *AzureProvider) IsAuthenticatedAgainstAzure() bool {
	_, err := armresources.NewClient(m.SubscriptionID, m.Credentials, nil)

	return err == nil
}
