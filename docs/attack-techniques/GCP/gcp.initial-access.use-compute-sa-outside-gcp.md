---
title: Steal and Use the GCE Default Service Account Token from Outside Google Cloud
---

# Steal and Use the GCE Default Service Account Token from Outside Google Cloud

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: GCP

## Mappings

- MITRE ATT&CK
    - Credential Access
  - Initial Access



## Description


Simulates the theft and use of GCE default service account credentials from outside of Google Cloud.

When a GCE instance is created, it is assigned a default service account
(<code>{project-number}-compute@developer.gserviceaccount.com</code>).
If an attacker gains access to the instance (for example through an SSRF vulnerability,
a compromised SSH key, or a command injection), they can extract the OAuth2 access token
from the <a href="https://cloud.google.com/compute/docs/metadata/overview">instance metadata service</a>
and use it from outside of Google Cloud.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCE instance running with the default compute service account
- The instance runs a startup script that extracts the service account OAuth2 token from the instance metadata service and writes it to the serial port

<span style="font-variant: small-caps;">Detonation</span>:

- Read the instance's serial port output to extract the stolen OAuth2 token
- Use the stolen token from outside Google Cloud to set labels on the GCE instance, generating a GCP Admin Activity audit log from a non-Google IP address

References:

- https://about.gitlab.com/blog/plundering-gcp-escalating-privileges-in-google-cloud-platform/
- https://securitylabs.datadoghq.com/articles/google-cloud-default-service-accounts/
- https://cloud.google.com/compute/docs/access/service-accounts#default_service_account


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.initial-access.use-compute-sa-outside-gcp
```
## Detection


Identify when a GCE default service account (<code>*-compute@developer.gserviceaccount.com</code>) is used from outside of Google Cloud
by analyzing GCP audit logs.

The GCE default service account should typically only be used from within Google Cloud (e.g., from a GCE instance).
Usage from external IP addresses with non-GCE user agents indicates potentially stolen credentials.

Detection criteria:

<ul>
  <li>Monitor GCP audit logs where the caller identity matches <code>*-compute@developer.gserviceaccount.com</code></li>
  <li>Filter for calls where the caller IP does not belong to Google's IP ranges</li>
  <li>Exclude calls with user agents containing <code>GCE</code> or <code>gcloud</code> (which indicate legitimate in-cloud usage)</li>
</ul>


