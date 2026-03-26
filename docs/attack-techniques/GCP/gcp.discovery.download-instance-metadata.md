---
title: Read GCE Instance Metadata via the Compute API
---

# Read GCE Instance Metadata via the Compute API


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Discovery



## Description


Reads the metadata of a GCE instance via the Compute Engine API, simulating an attacker
who has obtained a service account token and uses it to enumerate running instances and
harvest secrets embedded in instance metadata fields such as <code>startup-script</code>.

Bootstrap scripts that install software, configure databases, or pull secrets from
environment variables are a common source of plaintext credentials in GCP environments.
Unlike the instance metadata server (169.254.169.254) which is only reachable from
within the VM, the Compute API can be queried remotely by any identity with the
<code>compute.instances.get</code> permission.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCE instance with a simulated <code>startup-script</code> metadata value
  containing embedded credentials

<span style="font-variant: small-caps;">Detonation</span>:

- Enumerate instances in the zone via the Compute API
- Fetch the full instance resource including all metadata fields
- Log the <code>startup-script</code> value if present

References:

- https://cloud.google.com/compute/docs/metadata/overview
- https://cloud.google.com/compute/docs/reference/rest/v1/instances/get


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.discovery.download-instance-metadata
```
## Detection


Identify unexpected reads of instance metadata via the Compute API by monitoring for
<code>compute.instances.get</code> and <code>compute.instances.list</code> events in GCP
Data Access audit logs originating from identities that do not normally perform Compute
Engine management operations.


