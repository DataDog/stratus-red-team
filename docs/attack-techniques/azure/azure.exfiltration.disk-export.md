---
title: Export Disk Through SAS URL
---

# Export Disk Through SAS URL


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: Azure

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Generate a public [Shared Access Signature (SAS)](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview) URL to download an Azure disk.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an Azure-managed disk

<span style="font-variant: small-caps;">Detonation</span>:

- Generated a Shared Access Signature (SAS) URL for the disk

References:

- https://powerzure.readthedocs.io/en/latest/Functions/operational.html#get-azurevmdisk
- https://zigmax.net/azure-disk-data-exfiltration/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate azure.exfiltration.disk-export
```
## Detection


Identify <code>Microsoft.Compute/disks/beginGetAccess/action</code> events in Azure Activity logs.

Sample event (redacted for clarity):

```json hl_lines="6"
{
  "resourceId": "/SUBSCRIPTIONS/<your-subscription-id>/RESOURCEGROUPS/RG-IKFFQ01Z/PROVIDERS/MICROSOFT.COMPUTE/DISKS/STRATUS-RED-TEAM-DISK",
  "evt": {
    "category": "Administrative",
    "outcome": "Success",
    "name": "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION"
  },
  "level": "Information",
  "properties": {
    "hierarchy": "ecc2b97b-844b-414e-8123-b925dddf87ed/2fd72d85-b49f-4e19-b567-4a8cb7301e8b",
    "message": "Microsoft.Compute/disks/beginGetAccess/action",
    "eventCategory": "Administrative",
    "entity": "/subscriptions/<your-subscription-id/resourceGroups/rg-ikffq01z/providers/Microsoft.Compute/disks/stratus-red-team-disk"
  }
}
```


