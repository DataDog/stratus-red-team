---
title: Reuse an Amazon Cognito Refresh Token
---

# Reuse an Amazon Cognito Refresh Token


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Persistence


- Threat Technique Catalog for AWS:
  
    - [Account Manipulation: Cognito Refresh Token Abuse](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.A006.html) (T1098.A006)
  


## Description


Establishes persistence by reusing a valid Amazon Cognito refresh token to obtain fresh access and ID tokens, without knowing the user's password or repeating the initial authentication flow. As long as the refresh token remains valid and has not been revoked, an attacker who has stolen it can keep minting new tokens.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cognito user pool and an app client with refresh tokens enabled
- Create a confirmed test user with a permanent password
- Obtain an initial refresh token for that user (simulating an attacker who has compromised a valid refresh token)

<span style="font-variant: small-caps;">Detonation</span>:

- Exchange the refresh token for new access and ID tokens by calling <code>cognito-idp:GetTokensFromRefreshToken</code>

Note: To avoid leaking secrets, the token values obtained during warm-up and detonation are never printed or persisted; only non-sensitive metadata indicating that the exchange succeeded is logged.

References:

- https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.A006.html
- https://aws.amazon.com/blogs/security/what-the-march-2026-threat-technique-catalog-update-means-for-your-aws-environment/
- https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetTokensFromRefreshToken.html


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.cognito-refresh-token-reuse
```
## Detection


Through CloudTrail's <code>GetTokensFromRefreshToken</code> event, with <code>eventSource</code> <code>cognito-idp.amazonaws.com</code>. A refresh-token exchange that originates from an unexpected IP address, user agent, or geolocation, or that occurs after the user's credentials are believed to have been rotated, is especially suspicious.


