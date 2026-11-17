---
title: Register an Attacker-Controlled Cognito User and Obtain AWS Credentials
---

# Register an Attacker-Controlled Cognito User and Obtain AWS Credentials


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Initial Access


- Threat Technique Catalog for AWS:
  
    - [Valid Accounts: Cloud Accounts](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1078.004.html) (T1078.004)
  


## Description


Self-registers a user in a public Amazon Cognito user pool, then exchanges the resulting
identity for AWS credentials through the associated Cognito identity pool.

Cognito user pools that allow self sign-up, combined with an identity pool that federates
authenticated users into an IAM role, let anyone on the internet obtain valid AWS
credentials for the target account. In this
technique the authenticated role has no permissions.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a Cognito user pool with a pre-sign-up Lambda trigger that auto-confirms new users (so no email/SMS confirmation is required).
- Create a public app client allowing the SRP authentication flow.
- Create a Cognito identity pool federating authenticated user pool users into an IAM role that has no permissions.

<span style="font-variant: small-caps;">Detonation</span>:

- Self-register a new user in the user pool (<code>SignUp</code>).
- Authenticate using the SRP flow (<code>InitiateAuth</code> then <code>RespondToAuthChallenge</code>).
- Exchange the resulting ID token for AWS credentials (<code>GetId</code> then <code>GetCredentialsForIdentity</code>).

References:

- https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/
- https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/
- https://github.com/RhinoSecurityLabs/cloudgoat/tree/master/cloudgoat/scenarios/aws/vulnerable_cognito


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.initial-access.cognito-self-signup
```
## Detection


You can ientify the self-registration and credential exchange in CloudTrail. A typical detonation
produces the following sequence of events, all from the same source IP and (unauthenticated)
caller:

<ul>
<li><code>SignUp</code> (<code>eventSource: cognito-idp.amazonaws.com</code>): a new user registering in the pool.</li>
<li><code>InitiateAuth</code> followed by <code>RespondToAuthChallenge</code>: the SRP authentication handshake.</li>
<li><code>GetCredentialsForIdentity</code> (<code>eventSource: cognito-identity.amazonaws.com</code>): the exchange of the user pool token for AWS credentials. Note that this is a data event that needs to be enabled separately (see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html">here</a>).</li>
</ul>


