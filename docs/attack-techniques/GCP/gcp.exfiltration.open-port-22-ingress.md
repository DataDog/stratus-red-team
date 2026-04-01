---
title: Open Ingress Port 22 on a Firewall Rule
---

# Open Ingress Port 22 on a Firewall Rule




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Exfiltration



## Description


Creates a GCP firewall rule that opens ingress TCP port 22 (SSH) to the world
(<code>0.0.0.0/0</code>) on a VPC network.

An attacker who has compromised a GCP environment may create such a rule to
establish SSH access to any VM instance in the affected network, or to exfiltrate
data by tunnelling traffic over SSH.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a VPC network

<span style="font-variant: small-caps;">Detonation</span>:

- Create a firewall rule named <code>&lt;vpc&gt;-allow-ssh</code> that allows TCP:22 ingress
  from <code>0.0.0.0/0</code>

Revert:

- Delete the firewall rule

References:

- https://cloud.google.com/vpc/docs/firewalls
- https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/insert
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/
- https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudVPC/unrestricted-ssh-access.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.exfiltration.open-port-22-ingress
```
## Detection


Identify when a firewall rule opening a sensitive port to the world is created by
monitoring for <code>v1.compute.firewalls.insert</code> events in GCP Admin Activity
audit logs where <code>sourceRanges</code> includes <code>0.0.0.0/0</code> and
<code>allowed[].ports</code> contains port 22.


