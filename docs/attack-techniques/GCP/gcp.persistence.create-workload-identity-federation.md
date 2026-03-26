---
title: Create a Workload Identity Federation Pool and Provider
---

# Create a Workload Identity Federation Pool and Provider




Platform: GCP

## Mappings

- MITRE ATT&CK
    - Persistence



## Description


Creates a Workload Identity Federation (WIF) pool and an X.509 provider within it,
then grants the pool's identities permission to impersonate a target service account.
This simulates an attacker who has obtained access to a GCP project and establishes
a persistent backdoor by acting as their own certificate authority: any machine that
holds a certificate signed by the attacker's CA can silently exchange it for GCP
access tokens impersonating the target service account, without ever creating a
service account key.

This is the GCP equivalent of AWS IAM Roles Anywhere.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a target service account

<span style="font-variant: small-caps;">Detonation</span>:

- Generate an attacker-controlled CA certificate and a client certificate signed by it
- Create a Workload Identity Pool named <code>stratus-red-team-wif-&lt;suffix&gt;</code>
- Create an X.509 provider within the pool, trusting the attacker CA
- Grant <code>roles/iam.workloadIdentityUser</code> on the target service account
  to all identities in the pool (any cert signed by the attacker CA can impersonate it)
- Write <code>ca.crt</code>, <code>client.crt</code>, and <code>client.key</code> to the current directory

Revert:

- Remove the <code>roles/iam.workloadIdentityUser</code> binding from the service account
- Delete the X.509 provider
- Delete the Workload Identity Pool
- Remove <code>ca.crt</code>, <code>client.crt</code>, and <code>client.key</code>

References:

- https://cloud.google.com/iam/docs/workload-identity-federation-with-x509-certificates
- https://cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.persistence.create-workload-identity-federation
```
## Detection


Identify when a Workload Identity Federation pool or provider is created by
monitoring for <code>google.iam.admin.v1.CreateWorkloadIdentityPool</code> and
<code>google.iam.admin.v1.CreateWorkloadIdentityPoolProvider</code> events in GCP
Admin Activity audit logs. Alert on unexpected creation, especially X.509 providers
which allow certificate-based authentication from outside GCP.


