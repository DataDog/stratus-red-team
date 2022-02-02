---
title: Backdoor Lambda Function Through Resource-Based Policy
---

# Backdoor Lambda Function Through Resource-Based Policy




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence

## Description


Establishes persistence by backdooring a lambda function to allow its invocation from an external AWS account.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Lambda function.

<span style="font-variant: small-caps;">Detonation</span>: 

- Modify the Lambda function resource-base policy to allow lambda:InvokeFunction from an external, fictitious AWS account.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.lambda-backdoor-function
```
## Detection


- Using CloudTrail's <code>AddPermission20150331</code> and <code>AddPermission20150331v2</code> events.

- Through [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html#access-analyzer-lambda), which triggers a finding when permissions are added to a Lambda function making it 
public or accessible from another account.


