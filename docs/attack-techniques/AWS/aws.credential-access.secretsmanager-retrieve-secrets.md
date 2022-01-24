---
title: Retrieve a High Number of Secrets Manager secrets
---

# Retrieve a High Number of Secrets Manager secrets 

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