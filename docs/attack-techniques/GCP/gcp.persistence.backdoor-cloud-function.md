---
title: Backdoor a Cloud Function by Granting Public Invoke Access
---

# Backdoor a Cloud Function by Granting Public Invoke Access

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Persistence



## Description


Grants unauthenticated invocation access to a Cloud Functions v2 function by adding
an IAM binding for <code>allUsers</code>. An attacker who has gained access to a GCP
project with Cloud Functions deployed may modify the function's IAM policy to expose
internal logic or data-processing pipelines to the public internet, enabling them to
trigger the function without credentials even after they lose their original access.

Note that the public access can be disabled at organization level. If that's the case,
the technique will still report as detonated because GCP returns a success to the call
and then ignores the change. It still does generate a audit log that can be used for
detection.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cloud Functions v2 function with a simple Python hello-world handler

<span style="font-variant: small-caps;">Detonation</span>:

- Read the current IAM policy for the function
- Add a binding granting <code>roles/cloudfunctions.invoker</code> to <code>allUsers</code>
  on the Cloud Functions resource
- Add a binding granting <code>roles/run.invoker</code> to <code>allUsers</code> on the
  underlying Cloud Run service (Cloud Functions v2 enforces invocation auth at the
  Cloud Run layer)

Revert:

- Remove the <code>allUsers</code> bindings from both the function and Cloud Run service

References:

- https://cloud.google.com/functions/docs/securing/managing-access-iam
- https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions/setIamPolicy


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.persistence.backdoor-cloud-function
```
## Detection


Identify when a Cloud Function or its underlying Cloud Run service IAM policy is
modified to grant access to <code>allUsers</code> or <code>allAuthenticatedUsers</code>
by monitoring for
<code>google.cloud.functions.v2.CloudFunctionsService.SetIamPolicy</code> and
<code>google.cloud.run.v2.Services.SetIamPolicy</code> events in GCP Admin Activity
audit logs where the request adds a binding with those principals. Cloud Functions v2
enforces invocation authentication at the Cloud Run layer, so the Cloud Run
<code>SetIamPolicy</code> event is the more critical signal.


