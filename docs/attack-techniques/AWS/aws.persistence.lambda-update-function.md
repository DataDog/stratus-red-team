---
title: Update or modify Lambda Function Code
---

# Update or modify Lambda Function Code


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Persistence

## Description


Establishes persistence by updating a lambda function's code with malicious code.
A further use case could be updating the code to exfiltrate data.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Lambda function.

<span style="font-variant: small-caps;">Detonation</span>: 

- Update the Lambda function code.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.lambda-update-function
```
## Detection

Through CloudTrail's <code>UpdateFunctionCode*</code> event.

