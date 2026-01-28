---
title: Azure ransomware via Storage Account Blob deletion
---

# Azure ransomware via Storage Account Blob deletion




Platform: Azure

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates Azure Storage ransomware activity that empties a storage account through individual Blob deletion, then uploads a ransom note.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an Azure Storage Account, with versioning enabled
- Create Storage Containers in the Storage Account, each with a large number blobs with random content and extensions

<span style="font-variant: small-caps;">Detonation</span>: 

- List all available storage containers and their blobs and their versions in the bucket
- Delete all blobs in each container one by one, using [DeleteBlob](https://learn.microsoft.com/en-us/rest/api/storageservices/delete-blob?tabs=microsoft-entra-id)
- List and delete all blobs _again_ to delete any backups created by versioning
- Upload a ransom note to the storage account

Note: The attack does not need to disable versioning, which does not protect against ransomware. This attack removes all versions of the objects in the bucket. 

References:
#TODO



## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.impact.blob-ransomware-individual-file-deletion
```
## Detection


You can detect ransomware activity by identifying abnormal patterns of blobs being downloaded or deleted in a storage account. 
In general, this can be done through [Blob storage events](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-event-overview)

Sample Blob storage event <code>DeleteBlob</code>, shortened for readability:

```json hl_lines="3 8 10"
{
  "operationName": "DeleteBlob",
  "category": "StorageDelete",
  "properties": {
    "accountName":"my-storage-account",
    "objectKey": "/my-storage-account/storage-container/somefolder/foo.bar"
  },
  "resourceId":"/subscriptions/ac382a89-52bf-4923-8abd-f1e4791cd48f/resourceGroups/my-resource-group/providers/Microsoft.Storage/storageAccounts/my-storage-account/blobServices/default"
}
```


