---
title: Enumerate Bedrock models in multiple regions
---

# Enumerate Bedrock models in multiple regions


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Discovery


- Threat Technique Catalog for AWS:
  
    - [Resource Hijacking: Cloud Service Hijacking - Bedrock LLM Abuse](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1496.A007.html) (T1496.A007)
  


## Description


Simulates an attacker enumerating Bedrock models in multiple regions. Attackers frequently use this enumeration technique after having compromised an access key, to use it to answer their prompts.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Perform <code>bedrock:InvokeModel</code> with <code>MaxTokensToSample = -1</code> in several regions to check if the Bedrock model <code>anthropic.claude-3-5-sonnet-20241022-v2:0</code> is available for use.

References:

- https://permiso.io/blog/exploiting-hosted-models
- https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.discovery.bedrock-enumerate-models-multiple-regions
```
## Detection


Through CloudTrail's <code>InvokeModel</code> events. 
These can be considered suspicious especially when performed by a long-lived access key, or when the calls span across multiple regions.


