package providers

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/google/uuid"
	"log"
	"os"
)

const azureSubscriptionIdEnvVarKey = "AZURE_SUBSCRIPTION_ID"

type AzureProvider struct {
	Initialized         bool
	Credentials         *azidentity.DefaultAzureCredential
	ClientOptions       *arm.ClientOptions
	SubscriptionID      string
	UniqueCorrelationId uuid.UUID // unique value injected in the user-agent, to differentiate Stratus Red Team executions
}

func (m *AzureProvider) Init() {
	// Default value for client options
	if m.ClientOptions == nil {
		m.ClientOptions = &arm.ClientOptions{
			ClientOptions: azcore.ClientOptions{
				Telemetry: policy.TelemetryOptions{ApplicationID: m.UniqueCorrelationId.String(), Disabled: false},
			},
		}
	}

	// Default value for subscription ID
	if m.SubscriptionID == "" {
		m.SubscriptionID = os.Getenv(azureSubscriptionIdEnvVarKey)
	}

	if len(m.SubscriptionID) == 0 {
		log.Fatal(azureSubscriptionIdEnvVarKey + " is not set.")
	}

	m.Initialized = true
}

func (m *AzureProvider) GetCredentials() *azidentity.DefaultAzureCredential {
	if !m.Initialized {
		m.Init()
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
