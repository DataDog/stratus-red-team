---
title: Execute Commands on Virtual Machine using Custom Script Extension
---

# Execute Commands on Virtual Machine using Custom Script Extension

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">false</span> 

Platform: Azure

## MITRE ATT&CK Tactics

- Execution

## Description

By utilizing the 'CustomScriptExtension' extension on a Virtual Machine, an attacker can pass PowerShell commands to the VM as SYSTEM.

References:

- https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
- https://github.com/hausec/Azure-Attack-Matrix/blob/main/Execution/AZT201/AZT201-2.md

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a virtual machine

<span style="font-variant: small-caps;">Detonation</span>:

- Configure and provision a Custom Script Extension for the virtual machine


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.execution.vm-custom-script-extension
```

## Detection

1. Look for <code>Microsoft.Compute/virtualMachines/extensions/write</code> events in Azure Activity logs
2. Review files on disk located in <code>C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension</code>