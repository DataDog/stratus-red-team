---
title: Invoke Bedrock Model
---

# Invoke Bedrock Model


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Impact

## Description


Simulates an attacker enumerating Bedrock models and then invoking the Anthropic Claude 3 Sonnet model to run inference using an arbitrary prompt. LLMjacking is an attack vector where attackers use stolen cloud credentials to run large language models, leading to unauthorized inference.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Enumerate foundation models that can be used in the current region using <code>bedrock:ListFoundationModels</code>.
- If Anthropic Claude 3 Sonnet (anthropic.claude-3-sonnet-20240229-v1:0) is not enabled, attempt to enable it using <code>bedrock:PutUseCaseForModelAccess</code>, <code>bedrock:ListFoundationModelAgreementOffers</code>, <code>bedrock:CreateFoundationModelAgreement</code>, <code>bedrock:PutFoundationModelEntitlement</code>
- Call <code>bedrock:InvokeModel</code> to run inference using the model.

References:

- https://permiso.io/blog/exploiting-hosted-models
- https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/
- https://sysdig.com/blog/growing-dangers-of-llmjacking/
- https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf

!!! note

	This technique attempts to enable and invoke the Bedrock model anthropic.claude-3-sonnet-20240229-v1:0. To do this, it creates a Bedrock use case request for Anthropic models with a fictitious company nam, website and use-case:

	a

	It is expected that this will cause AWS to automatically send you an email entitled <code>You accepted an AWS Marketplace offer</code>. 
	Only Anthropic models require this. 
	If you want to use a different model, you can set the STRATUS_RED_TEAM_BEDROCK_MODEL environment variable to the model ID you want to use (see the list [here](https://docs.aws.amazon.com/bedrock/latest/userguide/model-ids.html)), and make sure it's available in your current region.

!!! note

	After enabling it, Stratus Red Team will not disable the Bedrock model anthropic.claude-3-sonnet-20240229-v1:0.
	While this should not incur any additional costs, you can disable the model by going to the [Model Access](https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/modelaccess) page in the AWS Management Console.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.impact.bedrock-invoke-model
```
