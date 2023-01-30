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
	Credentials         *azidentity.DefaultAzureCredential
	ClientOptions       *arm.ClientOptions
	SubscriptionID      string
	UniqueCorrelationId uuid.UUID // unique value injected in the user-agent, to differentiate Stratus Red Team executions
}

func NewAzureProvider(uuid uuid.UUID) *AzureProvider {
	subscriptionID := os.Getenv(azureSubscriptionIdEnvVarKey)
	if len(subscriptionID) == 0 {
		log.Fatal(azureSubscriptionIdEnvVarKey + " is not set.")
	}
	creds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}

	var DefaultClientOptions = arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Telemetry: policy.TelemetryOptions{ApplicationID: uuid.String(), Disabled: false},
		},
	}
	return &AzureProvider{
		Credentials:         creds,
		ClientOptions:       &DefaultClientOptions,
		SubscriptionID:      subscriptionID,
		UniqueCorrelationId: uuid,
	}
}

func (m *AzureProvider) GetCredentials() *azidentity.DefaultAzureCredential {
	return m.Credentials
}

func (m *AzureProvider) IsAuthenticatedAgainstAzure() bool {
	_, err := armresources.NewClient(m.SubscriptionID, m.Credentials, nil)

	return err == nil
}
