---
title: Retrieve a High Number of Secrets Manager secrets
---

# Retrieve a High Number of Secrets Manager secrets


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Retrieves a high number of Secrets Manager secrets, through secretsmanager:GetSecretValue.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create multiple secrets in Secrets Manager.

<span style="font-variant: small-caps;">Detonation</span>: 

- Enumerate the secrets through secretsmanager:ListSecrets
- Retrieve each secret value, one by one through secretsmanager:GetSecretValue


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.secretsmanager-retrieve-secrets
```
## Detection


Identify principals retrieving a high number of secrets, through CloudTrail's GetSecretValue event.

The following may be use to tune the detection, or validate findings:

- Principals who do not usually call secretsmanager:GetSecretValue
- Attempts to call GetSecretValue resulting in access denied errors

