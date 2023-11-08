---
title: Overwrite Lambda Function Code
---

# Overwrite Lambda Function Code


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Persistence

## Description


Establishes persistence by overwriting a Lambda function's code. 
A further, more advanced, use-case could be updating the code to exfiltrate the data processed by the Lambda function at runtime.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Lambda function.

<span style="font-variant: small-caps;">Detonation</span>: 

- Update the Lambda function code.

References:

- https://research.splunk.com/cloud/aws_lambda_updatefunctioncode/
- Expel's AWS security mindmap


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.lambda-overwrite-code
```
## Detection


Through CloudTrail's <code>UpdateFunctionCode*</code> event, e.g. <code>UpdateFunctionCode20150331v2</code>.


