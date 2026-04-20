---
title: Disable VPC Flow Logs on a Subnet
---

# Disable VPC Flow Logs on a Subnet


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Defense Evasion



## Description


Disables VPC flow logging on a subnet by patching its log configuration.
VPC flow logs record network traffic metadata for all VM instances in a subnet,
providing visibility for network monitoring and forensic investigation.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a VPC network
- Create a subnet with VPC flow logs enabled

<span style="font-variant: small-caps;">Detonation</span>:

- Disable VPC flow logs on the subnet by patching its <code>logConfig.enable</code> field to <code>false</code>

Revert:

- Re-enable VPC flow logs on the subnet

References:

- https://cloud.google.com/vpc/docs/using-flow-logs
- https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks/patch
- https://github.com/GoogleCloudPlatform/security-analytics/blob/main/src/3.02/3.02.md
- https://securitylabs.datadoghq.com/cloud-security-atlas/attacks/removing-vpc-flow-logs/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.defense-evasion.remove-vpc-flow-logs
```
## Detection


Identify when VPC flow logging is disabled on a subnet by monitoring for
<code>v1.compute.subnetworks.patch</code> events in GCP Admin Activity audit logs
where the request sets <code>logConfig.enable</code> to <code>false</code>.


