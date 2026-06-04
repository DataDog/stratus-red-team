---
title: Azure Blob Storage ransomware through Customer-Managed Key Vault key and vault deletion
---

# Azure Blob Storage ransomware through Customer-Managed Key Vault key and vault deletion




Platform: Azure

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Simulates Azure Blob Storage ransomware activity that changes the storage account's server-side encryption to use a Customer-Managed Key (CMK) from a Key Vault that the attacker controls, then deletes the Key Vault to render all data in the storage account inaccessible.

Unlike encryption scope-based ransomware, this technique operates at the storage account level — the attacker does not need to re-upload individual blobs. By rotating the storage account's encryption key to an attacker-controlled Key Vault key and then deleting the vault, all blobs in the account become inaccessible.

Note that due to Azure's purge protection feature (, the Key Vault and key remain soft-deleted and recoverable within the retention period.

!!! warning

	This technique requires the <code>Key Vault Administrator</code> role on your Azure subscription in addition to any other roles (e.g. <code>Contributor</code>). Without it, the detonation will fail with a 403 error when attempting to delete the Key Vault key.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Azure Storage Account with a system-assigned managed identity
- Create an Azure Key Vault without purge protection
- Grant the storage account the "Key Vault Crypto Service Encryption User" role on the Key Vault
- Create multiple storage containers in the account

<span style="font-variant: small-caps;">Detonation</span>:

- Create a number of blobs in the containers with random content and file extensions
- Enable purge protection on the Key Vault (generates MICROSOFT.KEYVAULT/VAULTS/WRITE activity log event)
- Create an RSA 2048 key in the Key Vault
- Update the storage account encryption settings to use the Customer-Managed Key from Key Vault
- Soft-delete the Key Vault key
- Attempt to purge the key (fails due to purge protection, but generates a log event)
- Soft-delete the Key Vault
- Attempt to purge the Key Vault (fails due to purge protection, but generates a log event)

References:

- https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview
- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.impact.blob-ransomware-service-storage-cmk
```
## Detection


You can detect this ransomware activity by monitoring for:

1. Storage account encryption configuration changes (<code>MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE</code>) where <code>properties.requestbody.properties.encryption.keySource</code> == <code>Microsoft.Keyvault</code>.
2. Key Vault key creation followed by deletion (<code>KeyCreate</code>, <code>KeyDelete</code>).
3. Key Vault deletion (<code>MICROSOFT.KEYVAULT/VAULTS/DELETE</code>) after being linked to a storage account's encryption.

Sample Azure Activity log event for storage account encryption update:

```json
{
  "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<storage-account-name>",
	"requestbody": {
		"properties": {
			"encryption": {
				"keySource": "Microsoft.Storage",
				"services": {
					"table": {
						"keyType": "Service"
					},
					"queue": {
						"keyType": "Service"
					}
				}
			},
	}
  }
}
```

Sample Azure Activity log event for Key Vault deletion:

```json
{
  "operationName": "MICROSOFT.KEYVAULT/VAULTS/DELETE",
  "category": "Administrative",
  "resultType": "Success",
  "properties": {
    "entity": "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>"
  }
}
```

Sample Key Vault audit event for key deletion:

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


