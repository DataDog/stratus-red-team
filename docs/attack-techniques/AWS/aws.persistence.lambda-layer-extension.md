---
title: Add a Malicious Lambda Extension
---

# Add a Malicious Lambda Extension


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by adding a malicious lambda extension.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a Lambda function and a lambda extension (layer).

<span style="font-variant: small-caps;">Detonation</span>: 

- Add the extension as a layer to the Lambda function.

References:

- https://www.clearvector.com/blog/lambda-spy/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.lambda-layer-extension
```
## Detection


Through CloudTrail's <code>UpdateFunctionConfiguration20150331v2<code> event.

While matching this event may be impractical and prone to false positives in most environments, the following can help to craft more precise detections:
		
Identify a call to <code>UpdateFunctionConfiguration20150331v2<code> where the layers field exists inside responseElements.
		
Identify a call to <code>UpdateFunctionConfiguration20150331v2<code> where the layers, within responseElements, include a layer that is not from the same account.


