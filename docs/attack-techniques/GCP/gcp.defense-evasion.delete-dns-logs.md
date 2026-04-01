---
title: Delete a Cloud DNS Logging Policy
---

# Delete a Cloud DNS Logging Policy




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Defense Evasion



## Description


Deletes a Cloud DNS policy that has query logging enabled.
Cloud DNS policies with logging record all DNS queries from VMs in the associated
networks to Cloud Logging, providing visibility into DNS-based communication.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a VPC network
- Create a Cloud DNS policy with query logging enabled, attached to the VPC network

<span style="font-variant: small-caps;">Detonation</span>:

- Delete the Cloud DNS policy, stopping query logging for the associated network

References:

- https://cloud.google.com/dns/docs/monitoring
- https://cloud.google.com/dns/docs/reference/v1/policies/delete
- https://attack.mitre.org/techniques/T1562/008/
- https://redcanary.com/threat-detection-report/trends/cloud-attacks/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.defense-evasion.delete-dns-logs
```
## Detection


Identify when a Cloud DNS policy is deleted by monitoring for
<code>dns.policies.delete</code> events in GCP Admin Activity audit logs.


