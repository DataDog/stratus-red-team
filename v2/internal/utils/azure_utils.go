package utils

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

	"io"
)

func GetAzureBlobClient(serviceURL string, subscriptionID string, defaultCredentials *azidentity.DefaultAzureCredential, clientOptions *arm.ClientOptions, params map[string]string) (*azblob.Client, error) {
	account := params["storage_account_name"]
	//Gets storage account keys to enable data-plan permissions
	armClient, err := armstorage.NewAccountsClient(subscriptionID, defaultCredentials, clientOptions)
	if err != nil {
		return nil, err
	}
	resp, err := armClient.ListKeys(context.Background(), params["resource_group_name"], account, nil)
	if err != nil {
		return nil, err
	}

	if resp.Keys == nil || len(resp.Keys) == 0 || resp.Keys[0].Value == nil {
		return nil, fmt.Errorf("No Keys returned from Storage")
	}
	key := *resp.Keys[0].Value
	cred, err := azblob.NewSharedKeyCredential(account, key)
	if err != nil {
		return nil, err
	}

	return azblob.NewClientWithSharedKeyCredential(serviceURL, cred, nil)

	//return azblob.NewClient(serviceURL, azure.GetCredentials(), nil)//, azure.ClientOptions) Disabled Because of "cannot use azure.ClientOptions (variable of type *arm.ClientOptions) as *azblob.ClientOptions value in argument to azblob.NewClient". May want to look into enabling it
}

func ListAllBlobVersions(client *azblob.Client) (map[string]map[string][]*string, error) {
	containerPager := client.NewListContainersPager(&azblob.ListContainersOptions{
		Include: azblob.ListContainersInclude{Metadata: true, Deleted: true},
	})
	result := make(map[string]map[string][]*string)
	for containerPager.More() {
		containerResp, err := containerPager.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("Error when enumerating storage containers:  %w", err)
		}
		for _, _container := range containerResp.ContainerItems {
			result[*_container.Name] = make(map[string][]*string)
			blobPager := client.NewListBlobsFlatPager(*_container.Name, &azblob.ListBlobsFlatOptions{
				Include: azblob.ListBlobsInclude{Deleted: true, Versions: true},
			})
			blobResp, err := blobPager.NextPage(context.Background())
			if err != nil {
				return nil, fmt.Errorf("Error when enumerating storage blobs in container %s: %w", *_container.Name, err)
			}
			for _, _blob := range blobResp.Segment.BlobItems {
				result[*_container.Name][*_blob.Name] = append(result[*_container.Name][*_blob.Name], _blob.VersionID)
			}
		}
	}
	return result, nil
}

func UploadBlob(client *azblob.Client, containerName string, blobName string, contents io.Reader) error {
	_, err := client.CreateContainer(context.Background(), containerName, nil)
	if err != nil {
		return err
	}
	_, err = client.UploadStream(context.Background(), containerName, blobName, contents, nil)
	return err
}
