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


Through CloudTrail's <code>UpdateFunctionConfiguration20150331v2</code> event.

While matching this event may be impractical and prone to false positives in most environments, the following can help to craft more precise detections:
		
- Identify calls to <code>UpdateFunctionConfiguration20150331v2</code> where the <code>responseElements</code> field contains <code>layer</code>, indicating that the function's layers were modified.
- Identify calls to <code>UpdateFunctionConfiguration20150331v2</code> where <code>responseElements.layers</code> includes a layer that's from a different AWS account.'





## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `lambda:UpdateFunctionConfiguration20150331v2`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "eugov-eastcentral-1r",
	      "eventCategory": "Management",
	      "eventID": "da929d96-8e20-475c-a810-973addd64769",
	      "eventName": "UpdateFunctionConfiguration20150331v2",
	      "eventSource": "lambda.amazonaws.com",
	      "eventTime": "2024-07-30T21:57:20Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "712967571683",
	      "requestID": "e8dffadf-9660-4d37-805f-b6dd8ac15959",
	      "requestParameters": {
	         "environment": {},
	         "functionName": "arn:aws:lambda:eugov-eastcentral-1r:712967571683:function:stratus-red-team-lambda-layer-simpleLambda",
	         "layers": [
	            "arn:aws:lambda:eugov-eastcentral-1r:712967571683:layer:stratus-red-team-lambda-layer-my-lambda-extension:1"
	         ]
	      },
	      "responseElements": {
	         "architectures": [
	            "x86_64"
	         ],
	         "codeSha256": "yoqgXJ3G1ROsFXLUfkxIKHbCiKf2eKCiIkxoktNUoNE=",
	         "codeSize": 258,
	         "description": "",
	         "environment": {},
	         "ephemeralStorage": {
	            "size": 512
	         },
	         "functionArn": "arn:aws:lambda:eugov-eastcentral-1r:712967571683:function:stratus-red-team-lambda-layer-simpleLambda",
	         "functionName": "stratus-red-team-lambda-layer-simpleLambda",
	         "handler": "stratus-red-team-lambda-layer-simpleLambda.handler",
	         "lastModified": "2024-07-30T21:57:15.000+0000",
	         "lastUpdateStatus": "InProgress",
	         "lastUpdateStatusReason": "The function is being created.",
	         "lastUpdateStatusReasonCode": "Creating",
	         "layers": [
	            {
	               "arn": "arn:aws:lambda:eugov-eastcentral-1r:712967571683:layer:stratus-red-team-lambda-layer-my-lambda-extension:1",
	               "codeSize": 2120,
	               "uncompressedCodeSize": 2672
	            }
	         ],
	         "loggingConfig": {
	            "logFormat": "Text",
	            "logGroup": "/aws/lambda/stratus-red-team-lambda-layer-simpleLambda"
	         },
	         "memorySize": 128,
	         "packageType": "Zip",
	         "revisionId": "7e710d48-c7d2-419c-b0bb-2f014bb742d8",
	         "role": "arn:aws:iam::712967571683:role/stratus-red-team-lambda-layer-lambda-role",
	         "runtime": "python3.10",
	         "runtimeVersionConfig": {
	            "runtimeVersionArn": "arn:aws:lambda:eugov-eastcentral-1r::runtime:fa339b789ded6e524b73b2ce2d1529eb06258c05ffa71ea5c8283c8dc106fbe3"
	         },
	         "snapStart": {
	            "applyOn": "None",
	            "optimizationStatus": "Off"
	         },
	         "state": "Active",
	         "timeout": 20,
	         "tracingConfig": {
	            "mode": "PassThrough"
	         },
	         "version": "$LATEST"
	      },
	      "sourceIPAddress": "211.219.255.238",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "lambda.eugov-eastcentral-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_cc572e3c-6c82-4c71-82f7-bf38ee5dbb4d",
	      "userIdentity": {
	         "accessKeyId": "AKIAUBN5AMJF3I0EG996",
	         "accountId": "712967571683",
	         "arn": "arn:aws:iam::712967571683:user/christophe",
	         "principalId": "AIDACL6MX7XSJHAMTCHM",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
