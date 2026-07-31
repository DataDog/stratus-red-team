---
title: Enable Local Authentication and Exfiltrate Azure AI Foundry API Keys
---

# Enable Local Authentication and Exfiltrate Azure AI Foundry API Keys


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Azure

## Mappings

- MITRE ATT&CK
    - Persistence
  - Credential Access



## Description


Re-enables local (key-based) authentication on an Azure AI Foundry (Cognitive Services) account that had it disabled, then retrieves the account's API keys.

An attacker with sufficient permissions on a Cognitive Services account can flip the `disableLocalAuth` property from `true` to `false`, then call `ListKeys` to obtain the primary and secondary API keys. These keys provide persistent, anonymous access to AI Foundry data-plane operations.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Azure Cognitive Services (AI Foundry) account with local authentication disabled

<span style="font-variant: small-caps;">Detonation</span>:

- Update the account to set `properties.disableLocalAuth` to `false`
- Call `ListKeys` to retrieve the account's API keys

References:

- https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth
- https://learn.microsoft.com/en-us/rest/api/cognitiveservices/accountmanagement/accounts/list-keys


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.persistence.exfiltrate-foundry-key
```
## Detection


Identify changes to the Cognitive Services account configuration through Azure Activity logs.

Look for two operations in sequence:

1. <code>Microsoft.CognitiveServices/accounts/write</code> — the account update that re-enables local authentication
2. <code>Microsoft.CognitiveServices/accounts/listKeys/action</code> — the key retrieval

Sample events (redacted for clarity):

```json hl_lines="3"
{
  "authorization": {
    "action": "Microsoft.CognitiveServices/accounts/write",
    "scope": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>"
  },
  "caller": "user@example.com",
  "category": {
    "value": "Administrative"
  },
  "operationName": {
    "value": "Microsoft.CognitiveServices/accounts/write"
  },
  "resourceId": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>",
  "status": {
    "value": "Started"
  },
  "properties": {
    "message": "Microsoft.CognitiveServices/accounts/write"
  }
}
```

```json hl_lines="3"
{
  "authorization": {
    "action": "Microsoft.CognitiveServices/accounts/listKeys/action",
    "scope": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>"
  },
  "caller": "user@example.com",
  "category": {
    "value": "Administrative"
  },
  "operationName": {
    "value": "Microsoft.CognitiveServices/accounts/listKeys/action"
  },
  "resourceId": "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.CognitiveServices/accounts/<account-name>",
  "status": {
    "value": "Succeeded"
  },
  "properties": {
    "statusCode": "OK",
    "message": "Microsoft.CognitiveServices/accounts/listKeys/action"
  }
}
```


