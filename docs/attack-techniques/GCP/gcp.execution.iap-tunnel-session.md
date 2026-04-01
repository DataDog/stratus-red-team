---
title: Grant IAP Tunnel Access to an External Identity
---

# Grant IAP Tunnel Access to an External Identity

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Execution
  - Lateral Movement



## Description


Grants an attacker-controlled service account the <code>roles/iap.tunnelResourceAccessor</code>
role at the project level. This role allows the identity to open IAP TCP forwarding tunnels
to any GCE instance in the project without requiring a firewall rule exposing SSH to the
internet, giving an attacker persistent, stealthy access to all VMs in the project.

This is the GCP equivalent of AWS Systems Manager <code>StartSession</code>.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCE instance to represent an active target
- Create a service account representing the attacker-controlled identity

<span style="font-variant: small-caps;">Detonation</span>:

- Add a project-level IAM binding granting <code>roles/iap.tunnelResourceAccessor</code>
  to the attacker-controlled service account

Revert:

- Remove the <code>roles/iap.tunnelResourceAccessor</code> binding

References:

- https://cloud.google.com/iap/docs/using-tcp-forwarding
- https://cloud.google.com/iap/docs/reference/rest/v1/V1/setIamPolicy
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.execution.iap-tunnel-session
```
## Detection


Identify when <code>roles/iap.tunnelResourceAccessor</code> is granted on the project
by monitoring for <code>SetIamPolicy</code> events on the project resource in GCP Admin
Activity audit logs. Alert when the binding's member is unexpected or newly created,
which indicates an attacker is preparing lateral movement via IAP tunnels.


