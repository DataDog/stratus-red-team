---
title: Attempt to Remove a GCP Project from its Organization
---

# Attempt to Remove a GCP Project from its Organization


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Defense Evasion



## Description


Attempts to remove a GCP project from its parent organization by moving it to an
attacker-controlled organization via the Cloud Resource Manager API. Removing a project
from an organization would allow an attacker to operate outside of Organization Policy
constraints, disable org-level audit log sinks, and evade security controls applied at
the organization node.

The API call generates an Admin Activity audit log event regardless of whether it succeeds.
In most environments the calling identity will lack the
<code>resourcemanager.projects.move</code> permission, so the call is expected to return a
permission-denied error — which is logged and ignored.

<span style="font-variant: small-caps;">Detonation</span>:

- Read current project metadata via the Cloud Resource Manager API
- Attempt to move the project to a different organization, which would detach it from the
  current organization

References:

- https://cloud.google.com/resource-manager/docs/creating-managing-projects
- https://cloud.google.com/resource-manager/reference/rest/v3/projects/move
- https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1666.A002.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.defense-evasion.remove-project-from-organization
```
## Detection


Identify calls to <code>google.cloud.resourcemanager.v3.Projects.MoveProject</code> (v3 API)
or <code>cloudresourcemanager.googleapis.com/projects.move</code> (v1 API) in
GCP Admin Activity audit logs, especially where the request attempts to change the
project parent to a different organization. Unexpected move attempts on the project
resource should be treated as high-severity events.


