---
title: Modify a GCE Instance Startup Script
---

# Modify a GCE Instance Startup Script

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 


Platform: GCP

## Mappings

- MITRE ATT&CK
    - Execution
  - Privilege Escalation



## Description


Stops a GCE instance, modifies its startup script to execute an attacker-controlled payload on the
next boot, and restarts it. An attacker with <code>compute.instances.setMetadata</code> permission
can use this technique to achieve persistent code execution and privilege escalation through the
instance's service account, without needing direct access to the instance.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCE instance (<code>e2-micro</code>, us-central1-a) with a benign startup script

<span style="font-variant: small-caps;">Detonation</span>:

- Stop the GCE instance and wait for it to reach <code>TERMINATED</code> state
- Replace the <code>startup-script</code> metadata value with a command that fetches
  and executes a remote payload
- Restart the instance

References:

- https://cloud.google.com/compute/docs/instances/startup-scripts/linux
- https://cloud.google.com/compute/docs/reference/rest/v1/instances/setMetadata
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/
- https://about.gitlab.com/blog/plundering-gcp-escalating-privileges-in-google-cloud-platform/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.execution.modify-gce-startup-script
```
## Detection


Identify when a GCE instance's startup script is modified by monitoring for
<code>v1.compute.instances.setMetadata</code> events in GCP Admin Activity audit logs
where the <code>metadata.items</code> field contains a <code>startup-script</code> key
that points to an external URL or contains suspicious commands. Correlate with
preceding <code>v1.compute.instances.stop</code> events on the same instance.


