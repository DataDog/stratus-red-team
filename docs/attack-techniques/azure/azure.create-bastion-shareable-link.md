---
title: Access Virtual Machine using Bastion shareable link
---

# Access Virtual Machine using Bastion shareable link

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique is slow to warm up and cleanup">slow</span> 


Platform: Azure

## MITRE ATT&CK Tactics


- Persistence

## Description


By utilizing the 'shareable link' feature on Bastions where it is enabled, an attacker can create a link to allow access to a virtual machine (VM) from untrusted networks. Public links generated for an Azure Bastion can allow VM network access to anyone with the generated URL.
NOTE: This technique will take 10-15 minutes to warmup, and 10-15 minutes to cleanup. This is due to the time to deploy an Azure Bastion.

References:

- https://blog.karims.cloud/2022/11/26/yet-another-azure-vm-persistence.html
- https://learn.microsoft.com/en-us/azure/bastion/shareable-link
- https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT509/AZT509/

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a VM and VNet
- Create an Azure Bastion host with access to the VM, and shareable links enabled
NOTE: Warm-up and cleanup can each take 10-15 minutes to create and destroy the Azure Bastion instance

<span style="font-variant: small-caps;">Detonation</span>: 

- Create an Azure Bastion shareable link with access to the VM

## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.persistence.bastion-shareable-link
```
## Detection

Identify Azure events of type <code>Microsoft.Network/bastionHosts/createshareablelinks/action</code> and <code>Microsoft.Network/bastionHosts/getShareablelinks/action</code>. A sample of <code>createshareablelinks</code> is shown below (redacted for clarity).

```json hl_lines="7"
  {
    "category": {
        "value": "Administrative",
        "localizedValue": "Administrative"
    },
    "level": "Informational",
    "operationName": {
        "value": "Microsoft.Network/bastionHosts/createshareablelinks/action",
        "localizedValue": "Creates shareable urls for the VMs under a bastion and returns the urls"
    },
    "resourceGroupName": "stratus-red-team-shareable-link-rg-tz6o",
    "resourceProviderName": {
        "value": "Microsoft.Network",
        "localizedValue": "Microsoft.Network"
    },
    "resourceType": {
        "value": "Microsoft.Network/bastionHosts",
        "localizedValue": "Microsoft.Network/bastionHosts"
    },
    "resourceId": "[removed]/resourceGroups/stratus-red-team-shareable-link-rg-tz6o/providers/Microsoft.Network/bastionHosts/stratus-red-team-shareable-link-bastion-tz6o",
    "status": {
        "value": "Succeeded",
        "localizedValue": "Succeeded"
    },
    "subStatus": {
        "value": "",
        "localizedValue": ""
    },
    "properties": {
        "eventCategory": "Administrative",
        "entity": "[removed]/resourceGroups/stratus-red-team-shareable-link-rg-tz6o/providers/Microsoft.Network/bastionHosts/stratus-red-team-shareable-link-bastion-tz6o",
        "message": "Microsoft.Network/bastionHosts/createshareablelinks/action",
        "hierarchy": "[removed]"
    },
}
```