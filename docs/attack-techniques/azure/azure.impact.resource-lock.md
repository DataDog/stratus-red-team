---
title: Delete Azure resource lock
---

# Delete Azure resource lock

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Azure

## Mappings

- MITRE ATT&CK
    - Impact



## Description


NOTE: Due to resource lock delays, the warmup and cleanup steps of this technique can take several minutes.

Disable Azure resource locks to allow resource deletion. Resource locks can be applied to any Azure resource, resource group, or subscription. This technique uses a lock on a resource group containing an Azure storage account as an example.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a storage account
- Set storage account as ReadOnly using an Azure resource lock at the resource group level

<span style="font-variant: small-caps;">Detonation</span>:

- Delete Azure resource lock

References:

- https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
- https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources



## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.impact.resource-lock
```
## Detection


Monitor Azure Activity Logs for resource lock changes, specifically <code>Microsoft.Authorization/locks/delete</code> operations. Once an attacker has removed a resource lock, they are able to modify and delete resources that were protected by that lock.

Sample Azure Activity Log event to monitor:

```json hl_lines="1 5"
    "operationName": {
        "value": "Microsoft.Authorization/locks/delete",
        "localizedValue": "Delete management locks"
    },
    "properties": {
        "properties": {
        "eventCategory": "Administrative",
        "entity": "/subscriptions/[SUBSCRIPTION-ID]/resourceGroups/stratus-red-team-lock-storage-71mu/providers/Microsoft.Authorization/locks/stratus-storage-lock-71mu",
        "message": "Microsoft.Authorization/locks/delete",
        "hierarchy": "[REMOVED]"
    }
```


