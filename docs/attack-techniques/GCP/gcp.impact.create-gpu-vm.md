---
title: Create a GCE GPU Virtual Machine
---

# Create a GCE GPU Virtual Machine


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Creates a GCE virtual machine instance with GPU accelerators, simulating an attacker creating GPU instances for cryptomining.

<span style="font-variant: small-caps;">Warm-up</span>:

- None

<span style="font-variant: small-caps;">Detonation</span>:

- Attempt to create a GCE instance with a GPU accelerator (nvidia-tesla-t4) attached

Note: The instance creation may fail in GCP projects without GPU quota. However, the GCP audit log is still generated
with the GPU accelerator request parameters, which is sufficient for detection rules to match on.

<span style="font-weight: bold;">⚠️ Warning:</span> If the instance is successfully created, it will incur GPU costs. Make sure to revert the technique after detonation to clean up created resources and avoid unnecessary costs.

References:

- https://www.mandiant.com/resources/blog/detecting-cryptomining-cloud
- https://cloud.google.com/blog/topics/threat-intelligence/detecting-cryptomining-using-vpc-flow-logs


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.create-gpu-vm
```
## Detection


Identify when GCE instances with GPU accelerators are created by monitoring for <code>v1.compute.instances.insert</code> or
<code>beta.compute.instances.insert</code> events in GCP Admin Activity audit logs where the request includes <code>guestAccelerators</code>.

Attackers frequently provision GPU-enabled VMs for cryptocurrency mining after compromising cloud credentials.
GPU VMs are significantly more expensive than standard VMs and are rarely used in most environments.

Detection criteria:

<ul>
  <li>Monitor <code>compute.instances.insert</code> events where the request contains <code>guestAccelerators.acceleratorCount</code></li>
  <li>Alert on any instance creation with GPU accelerators, especially from unusual principals or outside of normal change windows</li>
  <li>Consider higher severity when the caller IP is associated with known anonymizing proxies or botnets</li>
</ul>


