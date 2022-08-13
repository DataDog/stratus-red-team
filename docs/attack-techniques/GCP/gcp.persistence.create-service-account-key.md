---
title: Create a GCP Service Account Key
---

# Create a GCP Service Account Key




Platform: GCP

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a service account key on an existing service account.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a service account

<span style="font-variant: small-caps;">Detonation</span>:

- Create a new key for the service account

References:

- https://expel.com/blog/incident-report-spotting-an-attacker-in-gcp/
- https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.persistence.create-service-account-key
```
## Detection


Using GCP Admin Activity audit logs event <code>google.iam.admin.v1.CreateServiceAccountKey</code>.


