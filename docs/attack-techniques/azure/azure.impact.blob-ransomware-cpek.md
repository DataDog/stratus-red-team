---
title: Azure Blob Storage ransomware through Customer-Provided Encryption Keys
---

# Azure Blob Storage ransomware through Customer-Provided Encryption Keys




Platform: Azure

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates Azure Blob Storage ransomware activity that encrypts files using Customer-Provided Encryption Keys (CPK).
This is the Azure equivalent of the AWS SSE-C ransomware technique.
The attacker downloads existing blobs and re-uploads them encrypted with a customer-provided AES-256 key that only they possess.
Without the key, the blobs cannot be read.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Azure Storage Account
- Create multiple storage containers in the account
- Create a number of blobs in the containers with random content and file extensions

<span style="font-variant: small-caps;">Detonation</span>:

- Download all blobs
- Re-upload each blob encrypted with a customer-provided AES-256 key
- Upload a ransom note

References:

- https://learn.microsoft.com/en-us/azure/storage/blobs/encryption-customer-provided-keys
- https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.impact.blob-ransomware-cpek
```
## Detection


You can detect this ransomware activity by monitoring for high volumes of <code>GetBlob</code> followed by <code>PutBlob</code> operations, especially when <code>PutBlob</code> requests include customer-provided encryption key headers (<code>x-ms-encryption-algorithm: AES256</code>).

In Azure Storage diagnostic logs, look for:

1. Unusual volume of read (<code>GetBlob</code>) followed by write (<code>PutBlob</code>) operations on the same blobs.
2. <code>PutBlob</code> operations with the <code>x-ms-encryption-algorithm</code> request header set to <code>AES256</code>, indicating customer-provided key usage.

Sample Azure Storage diagnostic log event for a PutBlob with customer-provided key:

```json
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
```


