---
title: Exfiltrate Azure Storage via public access
---

# Exfiltrate Azure Storage via public access


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Azure

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Modify storage policies to download content in an Azure storage account.

References:

- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
- https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a storage account with anonymous blob access disabled
- Create a storage container with an empty test file

<span style="font-variant: small-caps;">Detonation</span>: 

- Enable anonymous blob access on the storage account
- Change storage container access level to allow public access (anonymous access to containers and blobs)
- Download test file from the public container


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.exfiltration.storage-public-access
```
## Detection


Monitor Azure Activity Logs for storage account property changes, specifically <code>Microsoft.Storage/storageAccounts/write</code> operations that modify storage access policies.

Sample Azure Activity Log event to monitor:

```json hl_lines="2 5"
    "operationName": {
        "value": "Microsoft.Storage/storageAccounts/write",
        "localizedValue": "Create/Update Storage Account"
    },
    "properties": {
        "requestbody": "{\"properties\":{\"allowBlobPublicAccess\":true}}",
        "eventCategory": "Administrative",
        "entity": "/subscriptions/[SUBSCRIPTION-ID]/resourceGroups/stratus-red-team-storage-storage-6m6k/providers/Microsoft.Storage/storageAccounts/stratusredteamstorage",
        "message": "Microsoft.Storage/storageAccounts/write",
        "hierarchy": "[REMOVED]"
    }


