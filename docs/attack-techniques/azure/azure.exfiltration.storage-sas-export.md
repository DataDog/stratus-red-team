---
title: Exfiltrate Azure Storage through SAS URL
---

# Exfiltrate Azure Storage through SAS URL


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Azure

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Generate a Shared Access Signature (SAS) to download content in an Azure storage account.

References:

- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
- https://microsoft.github.io/Azure-Threat-Research-Matrix/Impact/AZT701/AZT701-2/

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a storage account with anonymous blob access disabled
- Create a storage container with an empty test file

<span style="font-variant: small-caps;">Detonation</span>:

- Generate a shared access signature (SAS) URL for the storage container
- Download test file from the container using SAS URL


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.exfiltration.storage-sas-export
```
## Detection


Monitor Azure Activity Logs for storage account property changes, specifically <code>Microsoft.Storage/storageAccounts/listKeys/action</code> operations. Once an attacker has accessed storage keys, they are able to generate a SAS URL for any storage the key has access to.

Sample Azure Activity Log event to monitor:

```json hl_lines="1 5"
    "operationName": {
        "value": "Microsoft.Storage/storageAccounts/listKeys/action",
        "localizedValue": "List Storage Account Keys"
    },
	"properties": {
        "eventCategory": "Administrative",
        "entity": "/subscriptions/[SUBSCRIPTION-ID]/resourceGroups/stratus-red-team-storage-storage-27n4/providers/Microsoft.Storage/storageAccounts/stratusredteamexport",
        "message": "Microsoft.Storage/storageAccounts/listKeys/action",
        "hierarchy": "[REMOVED]"
    }


