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

var DefaultClientOptions = arm.ClientOptions{
	ClientOptions: azcore.ClientOptions{
		Telemetry: policy.TelemetryOptions{ApplicationID: UniqueExecutionId.String(), Disabled: false},
	},
}

var azureProvider = AzureProvider{
	UniqueCorrelationId: UniqueExecutionId,
	SubscriptionID:      os.Getenv(azureSubscriptionIdEnvVarKey),
	ClientOptions:       &DefaultClientOptions,
}

func Azure() *AzureProvider {
	return &azureProvider
}

func (m *AzureProvider) GetCredentials() *azidentity.DefaultAzureCredential {

	if len(m.SubscriptionID) == 0 {
		log.Fatal(azureSubscriptionIdEnvVarKey + " is not set.")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to pull the result: %v", err)
	}
	m.Credentials = cred

	return m.Credentials
}

func (m *AzureProvider) IsAuthenticatedAgainstAzure() bool {

	cred := m.GetCredentials()
	_, err := armresources.NewClient(m.SubscriptionID, cred, nil)

	return err == nil
}
