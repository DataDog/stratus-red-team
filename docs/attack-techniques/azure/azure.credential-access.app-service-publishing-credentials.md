---
title: Retrieve App Service Publishing Credentials
---

# Retrieve App Service Publishing Credentials


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Azure

## Mappings

- MITRE ATT&CK
    - Credential Access



## Description


Retrieves the publishing profile of an Azure App Service (Web App), which contains FTP and Web Deploy credentials in cleartext.

An attacker with read-or-higher access to an App Service can call the `publishxml` ARM action to download the publishing profile, without needing access to any Key Vault or secret store. The returned XML document contains `userName` and `userPWD` attributes that grant direct FTP and Web Deploy access to the application host. These credentials can then be used for lateral movement or to deploy malicious code to the running application.

This technique was observed in the STORM-2949 intrusion, where the threat actor harvested App Service publishing credentials to move from a compromised identity into application hosts.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Azure App Service (Linux Web App) in the West US 2 region

Note: This technique deploys to West US 2 rather than West US. App Service plan quota in smaller regions such as West US is frequently 0, which causes the deployment to fail. Larger regions like West US 2 have more spare capacity.

<span style="font-variant: small-caps;">Detonation</span>:

- Call the `listPublishingProfileXMLWithSecrets` action on the App Service to retrieve the publishing profile containing FTP and Web Deploy credentials

References:

- https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.credential-access.app-service-publishing-credentials
```
## Detection


Identify the <code>Microsoft.Web/sites/publishxml/action</code> operation in Azure Activity logs.

Sample event (redacted for clarity):

```json hl_lines="6"
{
  "resourceId": "/SUBSCRIPTIONS/<your-subscription-id>/RESOURCEGROUPS/STRATUS-RED-TEAM-ASP-CRED-RG/PROVIDERS/MICROSOFT.WEB/SITES/SRT-ASP-CRED",
  "evt": {
    "category": "Administrative",
    "outcome": "Success",
    "name": "MICROSOFT.WEB/SITES/PUBLISHXML/ACTION"
  },
  "level": "Information",
  "properties": {
    "message": "Microsoft.Web/sites/publishxml/action",
    "eventCategory": "Administrative",
    "entity": "/subscriptions/<your-subscription-id>/resourceGroups/stratus-red-team-asp-cred-rg/providers/Microsoft.Web/sites/srt-asp-cred"
  }
}
```

Note that this operation is logged even when the App Service has only basic (publishing) authentication disabled.


