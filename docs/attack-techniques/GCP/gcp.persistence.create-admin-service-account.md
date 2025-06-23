---
title: Create an Admin GCP Service Account
---

# Create an Admin GCP Service Account




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Persistence
  - Privilege Escalation



## Description


Establishes persistence by creating a new service account and assigning it 
<code>owner</code> permissions inside the current GCP project.

<span style="font-variant: small-caps;">Warm-up</span>: None

<span style="font-variant: small-caps;">Detonation</span>:

- Create a service account
- Update the current GCP project's IAM policy to bind the service account to the <code>owner</code> role'

References:

- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.persistence.create-admin-service-account
```
## Detection


Using the following GCP Admin Activity audit logs events:

- <code>google.iam.admin.v1.CreateServiceAccount</code>
- <code>SetIamPolicy</code> with <code>resource.type=project</code>


