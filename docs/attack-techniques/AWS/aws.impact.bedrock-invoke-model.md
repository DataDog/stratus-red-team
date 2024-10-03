---
title: Invoke Bedrock Model
---

# Invoke Bedrock Model


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Impact

## Description


Simulates an attacker enumerating Bedrock models and then invoking Anthropic Claude 2 to run inference using the provided prompt. LLMjacking is an attack vector where attackers use stolen cloud credentials to run large language models, leading to unauthorized inference. This technique demonstrates how attackers can use Bedrock to run inference on Anthropic Claude 2 to generate responses to prompts.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Perform <code>bedrock:ListFoundationModels</code> to enumerate foundation models that can be used in the current region.
- Perform <code>bedrock:InvokeModel</code> to invoke Claude 2.

References:

- https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/
- https://sysdig.com/blog/growing-dangers-of-llmjacking/
- https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.bedrock-invoke-model
```
## Detection


Through CloudTrail's <code>ListFoundationModels</code> and <code>InvokeModel</code> events. 
If model invocation logging is enabled, invocations requests are logged on CloudWatch and/or S3 buckets with additional details, including prompt content and response. This greatly helps in detecting malicious invocations.


