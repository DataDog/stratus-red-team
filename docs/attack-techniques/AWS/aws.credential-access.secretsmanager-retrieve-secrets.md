# Retrieve a High Number of Secrets Manager secrets

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Retrieves a high number of Secrets Manager secrets, through secretsmanager:GetSecretValue.

Warm-up: Create multiple secrets in Secrets Manager.

Detonation: Enumerate the secrets through secretsmanager:ListSecrets, then retrieve their value through secretsmanager:GetSecretValue.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.secretsmanager-retrieve-secrets
```