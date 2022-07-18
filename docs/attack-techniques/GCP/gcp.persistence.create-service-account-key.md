---
title: Create a GCP Service Account Key
---

# Create a GCP Service Account Key




Platform: GCP

## MITRE ATT&CK Tactics


- Persistence

## Description


Establishes persistence by creating a service account key on an existing service account.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a service account

<span style="font-variant: small-caps;">Detonation</span>:

- Create a new key for the service account


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.persistence.create-service-account-key
```
## Detection


Using GCP Admin Activity audit logs event <code>google.iam.admin.v1.CreateServiceAccountKey</code>.


