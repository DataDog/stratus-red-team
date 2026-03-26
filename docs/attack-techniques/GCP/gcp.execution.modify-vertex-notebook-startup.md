---
title: Inject a Malicious Startup Script into a Vertex AI Workbench Instance
---

# Inject a Malicious Startup Script into a Vertex AI Workbench Instance

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 


Platform: GCP

## Mappings

- MITRE ATT&CK
    - Execution
  - Privilege Escalation



## Description


Modifies a Vertex AI Workbench (user-managed notebook) instance to execute a
remote script on the next start by injecting a malicious URL into the instance's
<code>post-startup-script</code> metadata field. An attacker with
<code>notebooks.instances.update</code> permission can use this technique to
achieve persistent code execution inside the notebook environment, run under
the instance's service account identity.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Vertex AI Workbench instance (<code>e2-standard-2</code>, us-central1-a)

<span style="font-variant: small-caps;">Detonation</span>:

- Patch the Workbench instance's GCE setup metadata to set
  <code>post-startup-script</code> to a fictitious attacker-controlled GCS URI
  (<code>gs://evil-attacker-&lt;project-id&gt;-&lt;random&gt;/malicious.sh</code>)

Revert:

- Remove the <code>post-startup-script</code> metadata key from the instance

References:

- https://cloud.google.com/vertex-ai/docs/workbench/user-managed/manage-notebooks-introduction
- https://cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances/patch


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.execution.modify-vertex-notebook-startup
```
## Detection


Identify when a Vertex AI Workbench instance's metadata is modified by monitoring
for <code>google.cloud.notebooks.v2.NotebookService.UpdateInstance</code> events in
GCP Admin Activity audit logs. Alert when the <code>post-startup-script</code> or
<code>startup-script</code> metadata fields are added or changed to external URLs,
which may indicate an attempt to establish persistent code execution in the notebook
environment.


