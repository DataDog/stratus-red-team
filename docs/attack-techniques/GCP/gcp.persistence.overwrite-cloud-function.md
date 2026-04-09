---
title: Overwrite a Cloud Function with Malicious Source Code
---

# Overwrite a Cloud Function with Malicious Source Code

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Persistence



## Description


Replaces the source code of an existing Cloud Functions v2 function with code that
exfiltrates runtime environment variables. This simulates supply-chain or insider
attacks where an adversary with write access to the function's source bucket — or
direct Cloud Functions update permissions — modifies the function to harvest secrets
injected via environment variables, mounted Secret Manager secrets, or service account
token metadata available at runtime.

The injected replacement function calls <code>env</code> and returns the output in
the HTTP response body, allowing an attacker to read any runtime secret by triggering
the function endpoint.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cloud Functions v2 function with a benign Python hello-world handler

<span style="font-variant: small-caps;">Detonation</span>:

- Build a replacement source zip in memory containing the malicious handler
- Upload the zip to the function's GCS source bucket
- Update the function's <code>buildConfig.source.storageSource</code> to reference
  the new zip and trigger a redeploy

Revert:

- Update the function's <code>buildConfig.source.storageSource</code> to point back
  to the original source object

References:

- https://cloud.google.com/functions/docs/deploying
- https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions/patch
- https://www.tenable.com/blog/confusedfunction-a-privilege-escalation-vulnerability-impacting-gcp-cloud-functions


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.persistence.overwrite-cloud-function
```
## Detection


Identify unexpected Cloud Function source updates by monitoring for
<code>google.cloud.functions.v2.CloudFunctionsService.UpdateFunction</code> events in
GCP Admin Activity audit logs. Alert on updates where the source object changes,
especially when the new object name does not follow the project's naming conventions.


