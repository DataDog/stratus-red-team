---
title: Create an EC2 Key Pair with a Suspicious Name
---

# Create an EC2 Key Pair with a Suspicious Name




Platform: AWS

## Mappings

- MITRE ATT&CK
    - Persistence


- Threat Technique Catalog for AWS:
  
    - [Account Manipulation: Additional Cloud Credentials](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.001.html) (T1098.001)
  


## Description


Creates an EC2 key pair using a short, generic name previously observed being reused across
unrelated compromised AWS environments. Attackers plant their own key pair so they can later
launch or access EC2 instances without relying on the credentials they used to gain initial access.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>:

- Call ec2:DescribeInstances filtered by the key name, to check whether the environment has
  been compromised before and the key pair is already in use.
- Call ec2:CreateKeyPair to create a new key pair with a known suspicious name.

References:

- https://securitylabs.datadoghq.com/articles/following-attackers-trail-in-aws-methodology-findings-in-the-wild/#atomic-indicator-ec2-keypair-creation


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.ec2-create-suspicious-keypair
```
## Detection


Identify calls to the CloudTrail event <code>CreateKeyPair</code>, optionally preceded shortly before
by a <code>DescribeInstances</code> call whose <code>requestParameters.filterSet</code> filters on
<code>key-name</code>.

Known suspicious key names observed reused across unrelated compromised environments include
<code>xg1</code> and <code>temp_key_pair</code> — matching <code>requestParameters.keyName</code>
against a list of such known-bad values is a high-confidence atomic indicator.


