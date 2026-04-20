---
title: Create GCE Instances in Multiple Zones
---

# Create GCE Instances in Multiple Zones




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Impact



## Description


Creates GCE instances across multiple zones, simulating an attacker hijacking compute resources for cryptomining across multiple availability zones.

<span style="font-variant: small-caps;">Warm-up</span>:

- None

<span style="font-variant: small-caps;">Detonation</span>:

- Create 6 <code>e2-micro</code> GCE instances in parallel across 6 different zones in multiple regions

<span style="font-weight: bold;">⚠️ Warning:</span> This technique creates real GCE instances. Make sure to revert the technique after detonation to clean up created resources and avoid unnecessary costs.

References:

- https://www.mandiant.com/resources/blog/detecting-cryptomining-cloud
- https://cloud.google.com/blog/topics/threat-intelligence/detecting-cryptomining-using-vpc-flow-logs


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.impact.create-instances-in-multiple-zones
```
## Detection


Identify when GCE instances are created across an unusually high number of zones by monitoring for
<code>v1.compute.instances.insert</code> or <code>beta.compute.instances.insert</code> events in GCP Admin Activity audit logs.

An attacker performing resource hijacking (e.g., cryptomining) typically creates instances across many zones
to maximize resource availability and evade per-zone quotas.

Detection criteria:

<ul>
  <li>Monitor <code>compute.instances.insert</code> events grouped by caller identity</li>
  <li>Count the number of distinct zones in which instances are created within a short time window (e.g., 5 minutes)</li>
  <li>Alert when the number of distinct zones exceeds a threshold (e.g., more than 5 zones)</li>
  <li>Exclude legitimate automation such as Managed Instance Groups (user agent containing <code>GCE Managed Instance Group</code>)</li>
</ul>


