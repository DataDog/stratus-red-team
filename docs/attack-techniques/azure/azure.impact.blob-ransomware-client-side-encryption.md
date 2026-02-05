---
title: Azure Blob Storage ransomware through Key Vault encryption scope
---

# Azure Blob Storage ransomware through Key Vault encryption scope




Platform: Azure

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates Azure Blob Storage ransomware activity that encrypts files using an encryption scope backed by a customer-managed Key Vault key, then deletes the key to render the data inaccessible.
Note that due to Azure's purge protection feature, it is impossible to hard-delete the key and the blobs remain recoverable.

You will need to have the <code>Key Vault Administrator</code> role on your Azure subscription to correctly warmup the technique.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Azure Storage Account with a system-assigned managed identity
- Create an Azure Key Vault without purge protection
- Grant the storage account the "Key Vault Crypto Service Encryption User" role on the Key Vault
- Create multiple storage containers in the account
- Create a number of blobs in the containers with random content and file extensions

<span style="font-variant: small-caps;">Detonation</span>:

- Enable purge protection on the Key Vault (to generate MICROSOFT.KEYVAULT/VAULTS/WRITE activity log event)
- Create an RSA 2048 key in the Key Vault
- Create an encryption scope on the storage account using the Key Vault key
- Download all blobs and re-upload them using the new encryption scope
- Soft-delete the Key Vault key
- Attempt to purge the key (fails due to purge protection, but logged)

References:

- [Storm-0501’s evolving techniques lead to cloud-based ransomware](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/)


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.impact.blob-ransomware-client-side-encryption
```
## Detection


You can detect this ransomware activity by monitoring for:

1. Encryption scope creation  (<code>MICROSOFT.STORAGE/STORAGEACCOUNTS/ENCRYPTIONSCOPES/WRITE</code>) followed by the deletion of the key (<code>KeyDelete</code>) used for encryption.
2. High volumes of <code>GetBlob</code> followed by <code>PutBlob</code> operations.

Sample Azure Activity log event for Key Vault creation:

```json
{
  "operationName": "MICROSOFT.KEYVAULT/VAULTS/WRITE",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>"
  }
}
```

Sample Azure Activity log event for Key Vault key deletion:

```json
{
  "operationName": "KeyDelete",
  "category": "AuditEvent",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>/keys/<key-name>"
  }
}
```

Sample event for encryption scope creation:

```json
{
  "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/ENCRYPTIONSCOPES/WRITE",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<storage-account-name>/encryptionScopes/<encryption-scope-name>"
  }
}
```


