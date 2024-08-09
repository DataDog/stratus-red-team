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



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `lambda:AddPermission20150331v2`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "ca-centralnorth-1r",
	      "eventCategory": "Management",
	      "eventID": "b67a9bba-d9da-4980-bf74-baed881b117d",
	      "eventName": "AddPermission20150331v2",
	      "eventSource": "lambda.amazonaws.com",
	      "eventTime": "2024-08-01T13:47:16Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "880896431042",
	      "requestID": "c84f1436-60be-4ad8-a6f7-f3c44d47df3a",
	      "requestParameters": {
	         "action": "lambda:InvokeFunction",
	         "functionName": "stratus-red-team-backdoor-f-func",
	         "principal": "*",
	         "statementId": "backdoor"
	      },
	      "responseElements": {
	         "statement": "{\"Sid\":\"backdoor\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ca-centralnorth-1r:880896431042:function:stratus-red-team-backdoor-f-func\"}"
	      },
	      "sourceIPAddress": "151.236.251.251",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "lambda.ca-centralnorth-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_a5b48423-fe4e-446d-a058-0f2b624cdfb1",
	      "userIdentity": {
	         "accessKeyId": "AKIAYALJGCQ7J893JO5I",
	         "accountId": "880896431042",
	         "arn": "arn:aws:iam::880896431042:user/christophe",
	         "principalId": "AIDAC4Q0BJF2SN7BSHFO",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
