package providers

import (
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/google/uuid"
)

const azureSubscriptionIdEnvVarKey = "AZURE_SUBSCRIPTION_ID"

type AzureProvider struct {
	Credentials         azcore.TokenCredential
	ClientOptions       *arm.ClientOptions
	SubscriptionID      string
	UniqueCorrelationId uuid.UUID // unique value injected in x-ms-client-request-id, to correlate Stratus Red Team executions in Azure Activity Logs
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
			Telemetry:       policy.TelemetryOptions{ApplicationID: correlationId.String(), Disabled: false},
			PerCallPolicies: []policy.Policy{newCorrelationIDPolicy(correlationId)},
		},
	}
	return p
}

func (m *AzureProvider) GetCredentials() azcore.TokenCredential {
	return m.Credentials
}

// NewBlobClient builds an azblob client wired with the provider's credentials and
// client options, so every blob request carries the Stratus correlation ID
// (x-ms-client-request-id) and telemetry. Prefer this over calling azblob.NewClient
// directly: data-plane clients use their own options type, and constructing them by
// hand makes it easy to accidentally drop the correlation policy.
func (m *AzureProvider) NewBlobClient(serviceURL string) (*azblob.Client, error) {
	return azblob.NewClient(serviceURL, m.Credentials, &azblob.ClientOptions{
		ClientOptions: m.ClientOptions.ClientOptions,
	})
}

func (m *AzureProvider) IsAuthenticatedAgainstAzure() bool {
	_, err := armresources.NewClient(m.SubscriptionID, m.Credentials, nil)

	return err == nil
}
