---
title: Create an EC2 Key Pair with a Suspicious Name
---

# Create an EC2 Key Pair with a Suspicious Name


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Persistence


- Threat Technique Catalog for AWS:
  
    - [Account Manipulation: Additional Cloud Credentials](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.001.html) (T1098.001)
  


## Description


Creates an EC2 key pair, simulating attackers planting their own key pair so they can later
launch or access EC2 instances without relying on the credentials they used to gain initial access.

By default, the key pair is named <code>key-stratus-red-team-<random suffix></code>, which
matches a "key*" naming convention associated with attacker-planted key pairs while still being
unique per detonation. To simulate a specific known suspicious name observed being reused across
unrelated compromised AWS environments (such as <code>xg1</code>), set the <code>STRATUS_RED_TEAM_KEY_PAIR</code>
environment variable to the desired key pair name.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>:

- Call ec2:DescribeInstances filtered by the key name, to check whether the key pair is
  already in use.
- Call ec2:CreateKeyPair to create a new key pair.

References:

- https://securitylabs.datadoghq.com/articles/following-attackers-trail-in-aws-methodology-findings-in-the-wild/#atomic-indicator-ec2-keypair-creation


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.ec2-create-suspicious-keypair
```
## Detection


Identify calls to the CloudTrail event <code>CreateKeyPair</code> where <code>requestParameters.keyName</code>
starts with <code>key</code> and the caller authenticated with an IAM user access key
(<code>userIdentity.accessKeyId</code> starting with <code>AKIA</code>) — a known suspicious
naming convention for attacker-planted key pairs, as opposed to a descriptive, project-scoped name.


