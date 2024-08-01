---
title: Retrieve And Decrypt SSM Parameters
---

# Retrieve And Decrypt SSM Parameters


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Retrieves and decrypts a high number (30) of SSM Parameters available in an AWS region.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create multiple SSM Parameters

<span style="font-variant: small-caps;">Detonation</span>: 

- Use ssm:DescribeParameters to list SSM Parameters in the current region
- Use ssm:GetParameters by batch of 10 (maximal supported value) to retrieve the values of the SSM Parameters


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.ssm-retrieve-securestring-parameters
```
## Detection


Identify principals retrieving a high number of SSM Parameters, through CloudTrail's <code>GetParameter</code> 
and <code>GetParameters</code> events. 
It is especially suspicious when parameters of type <code>SecretString</code> are retrieved, indicated when 
<code>requestParameters.withDecryption</code> is set to <code>true</code> in the CloudTrail events.

The following may be use to tune the detection, or validate findings:

- Principals who do not usually call ssm:GetParameter(s)
- Attempts to call ssm:GetParameter(s) resulting in access denied errors





## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:



??? "View raw detonation logs"

    ```json hl_lines=""

    []
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
