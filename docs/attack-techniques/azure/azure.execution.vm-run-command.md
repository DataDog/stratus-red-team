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

1. Look for <code>Microsoft.Compute/virtualMachines/runCommand/action</code> events in Azure Activity logs
2. Review files on disk located in <code>C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows</code>, <code>/var/lib/waagent/run-command/download/</code>, or <code>/var/lib/waagent/Microsoft.CPlat.Core.RunCommandLinux-VERSIONNUMER</code>