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





## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `lambda:UpdateFunctionCode20150331v2`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "ap-westeast-2r",
	      "eventCategory": "Management",
	      "eventID": "4672b74f-2466-4784-b3fb-5b4db904a995",
	      "eventName": "UpdateFunctionCode20150331v2",
	      "eventSource": "lambda.amazonaws.com",
	      "eventTime": "2024-08-01T13:52:02Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "266106314375",
	      "requestID": "4ae683f5-13be-4305-8267-0d2fc47dd663",
	      "requestParameters": {
	         "dryRun": false,
	         "fullyQualifiedArn": {
	            "arnPrefix": {
	               "account": "266106314375",
	               "partition": "aws",
	               "region": "ap-westeast-2r"
	            },
	            "functionQualifier": {},
	            "relativeId": {
	               "functionName": "stratus-red-team-olc-func-vayhjqkdav"
	            }
	         },
	         "functionName": "arn:aws:lambda:ap-westeast-2r:266106314375:function:stratus-red-team-olc-func-vayhjqkdav",
	         "publish": true
	      },
	      "responseElements": {
	         "architectures": [
	            "x86_64"
	         ],
	         "codeSha256": "Pt1c8vVaBygmNtAeSyjlpdy7r8nHRqJAAL++HEGlQkc=",
	         "codeSize": 211,
	         "description": "",
	         "environment": {},
	         "ephemeralStorage": {
	            "size": 512
	         },
	         "functionArn": "arn:aws:lambda:ap-westeast-2r:266106314375:function:stratus-red-team-olc-func-vayhjqkdav:1",
	         "functionName": "stratus-red-team-olc-func-vayhjqkdav",
	         "handler": "lambda.lambda_handler",
	         "lastModified": "2024-08-01T13:52:02.000+0000",
	         "loggingConfig": {
	            "logFormat": "Text",
	            "logGroup": "/aws/lambda/stratus-red-team-olc-func-vayhjqkdav"
	         },
	         "memorySize": 128,
	         "packageType": "Zip",
	         "revisionId": "80497f44-ab61-49ef-b235-4166136e3d10",
	         "role": "arn:aws:iam::266106314375:role/stratus-red-team-olc-lambda-vayhjqkdav",
	         "runtime": "python3.9",
	         "runtimeVersionConfig": {
	            "runtimeVersionArn": "arn:aws:lambda:ap-westeast-2r::runtime:be9e7121d3264b1e86158b38dbbb656c23dff979eb481793ee37b9e2b79fda22"
	         },
	         "snapStart": {
	            "applyOn": "None",
	            "optimizationStatus": "Off"
	         },
	         "state": "Pending",
	         "stateReason": "The function is being created.",
	         "stateReasonCode": "Creating",
	         "timeout": 3,
	         "tracingConfig": {
	            "mode": "PassThrough"
	         },
	         "version": "1"
	      },
	      "sourceIPAddress": "253.8.50.132",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "lambda.ap-westeast-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_856369f3-2721-42df-974b-3243863d6f55",
	      "userIdentity": {
	         "accessKeyId": "AKIAKHYV6FI4F4CJQMDV",
	         "accountId": "266106314375",
	         "arn": "arn:aws:iam::266106314375:user/christophe",
	         "principalId": "AIDAHSKGTD3UIOD3DXXY",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
