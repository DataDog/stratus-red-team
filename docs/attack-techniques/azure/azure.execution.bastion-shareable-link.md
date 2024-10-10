---
title: Execute Command on Virtual Machine using Custom Script Extension
---

# Execute Command on Virtual Machine using Custom Script Extension

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique is slow to warm up and cleanup">slow</span> 


Platform: Azure

## MITRE ATT&CK Tactics


- Execution

## Description


By utilizing the 'CustomScriptExtension' extension on a Virtual Machine, an attacker can pass PowerShell commands to the VM as SYSTEM.
NOTE: This technique will take 10-15 minutes to warmup, and 10-15 minutes to cleanup. This is due to the time to deploy an Azure Bastion.

References:

- https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
- https://microsoft.github.io/Azure-Threat-Research-Matrix/Execution/AZT301/AZT301-2/

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a virtual machine

<span style="font-variant: small-caps;">Detonation</span>: 

- Configure a custom script extension for the virtual machine


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.execution.vm-custom-script-extension
```
## Detection


Identify Azure events of type <code>Microsoft.Compute/virtualMachines/extensions/write</code>. Sample below (redacted for clarity).

```json hl_lines="7"
{
  "duration": 0,
  "resourceId": "/SUBSCRIPTIONS/<your-subscription-id>/RESOURCEGROUPS/RG-HAT6H48Q/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM-HAT6H48Q/EXTENSIONS/CUSTOMSCRIPTEXTENSION-STRATUS-EXAMPLE",
  "evt": {
    "category": "Administrative",
    "outcome": "Start",
    "name": "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE"
  },
  "resource_name": "customscriptextension-stratus-example",
  "time": "2022-06-18T19:57:27.8617215Z",
  "properties": {
    "hierarchy": "ecc2b97b-844b-414e-8123-b925dddf87ed/<your-subscription-id>",
    "message": "Microsoft.Compute/virtualMachines/extensions/write",
    "eventCategory": "Administrative",
    "entity": "/subscriptions/<your-subscription-id>/resourceGroups/rg-hat6h48q/providers/Microsoft.Compute/virtualMachines/vm-hat6h48q/extensions/CustomScriptExtension-Stratus-Example"
  },
}
```