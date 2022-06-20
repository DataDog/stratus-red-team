---
title: Execute Commands on Virtual Machine using Run Command
---

# Execute Commands on Virtual Machine using Run Command

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Azure

## MITRE ATT&CK Tactics


- Execution

## Description


By utilizing the 'RunCommand' feature on a Virtual Machine, an attacker can pass:

- Windows: PowerShell commands to the VM as SYSTEM.
- Linux: Shell commands to the VM as root.

References:

- https://docs.microsoft.com/en-us/azure/virtual-machines/windows/run-command
- https://docs.microsoft.com/en-us/azure/virtual-machines/linux/run-command
- https://github.com/hausec/Azure-Attack-Matrix/blob/main/Execution/AZT201/AZT201-1.md

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a virtual machine

<span style="font-variant: small-caps;">Detonation</span>: 

- Invoke a RunCommand on the target virtual machine


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.execution.vm-run-command
```
## Detection


Identify <code>Microsoft.Compute/virtualMachines/runCommand/action</code> 
and <code>Microsoft.Compute/virtualMachines/runCommands/write</code> events in Azure Activity logs.

Sample event (redacted for clarity):

```json hl_lines="7"
{
    "caller": "you@domain.tld",
	"eventTimestamp": "2022-06-01T11:39:35.6986539Z",
    "id": "/subscriptions/<your-subscription-id>/resourceGroups/rg-4x3tj2hb/providers/Microsoft.Compute/virtualMachines/vm-4x3tj2hb/events/25235036-3b0c-46e7-97d0-5bea476a6ab8/ticks/637896803756986539",
    "level": "Informational",
    "operationName": {
        "value": "Microsoft.Compute/virtualMachines/runCommand/action",
        "localizedValue": "Run Command on Virtual Machine"
    },
    "resourceGroupName": "rg-4x3tj2hb",
    "resourceProviderName": {
        "value": "Microsoft.Compute",
        "localizedValue": "Microsoft.Compute"
    },
    "resourceType": {
        "value": "Microsoft.Compute/virtualMachines",
        "localizedValue": "Microsoft.Compute/virtualMachines"
    },
    "resourceId": "/subscriptions/<your-subscription-id>/resourceGroups/rg-4x3tj2hb/providers/Microsoft.Compute/virtualMachines/vm-4x3tj2hb",
    "status": {
        "value": "Succeeded",
        "localizedValue": "Succeeded"
    },
    "properties": {
        "eventCategory": "Administrative",
        "entity": "/subscriptions/<your-subscription-id>/resourceGroups/rg-4x3tj2hb/providers/Microsoft.Compute/virtualMachines/vm-4x3tj2hb",
        "message": "Microsoft.Compute/virtualMachines/runCommand/action",
        "hierarchy": "<your-tenant-id>/<your-subscription-id>"
    },
    "relatedEvents": []
}
```


