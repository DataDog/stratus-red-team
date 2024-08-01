---
title: Retrieve a High Number of Secrets Manager secrets (Batch)
---

# Retrieve a High Number of Secrets Manager secrets (Batch)


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Credential Access

## Description


Retrieves a high number of Secrets Manager secrets by batch, through <code>secretsmanager:BatchGetSecretValue</code> (released Novemeber 2023). 
An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets.


<span style="font-variant: small-caps;">Warm-up</span>: 

- Create multiple secrets in Secrets Manager.

<span style="font-variant: small-caps;">Detonation</span>: 

- Dump all secrets by batch of 10, using <code>secretsmanager:BatchGetSecretValue</code>.

References:

- https://aws.amazon.com/blogs/security/how-to-use-the-batchgetsecretsvalue-api-to-improve-your-client-side-applications-with-aws-secrets-manager/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.credential-access.secretsmanager-batch-retrieve-secrets
```
## Detection


Identify principals that attempt to retrieve secrets by batch, through CloudTrail's <code>BatchGetSecretValue</code> event. Sample event:

```json
{
  "eventSource": "secretsmanager.amazonaws.com",
  "eventName": "BatchGetSecretValue",
  "requestParameters": {
    "filters": [
      {
        "key": "tag-key",
        "values": [
          "StratusRedTeam"
        ]
      }
    ]
  },
  "responseElements": null,
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "012345678901"
}
```

Although <code>BatchGetSecretValue</code> requires a list of secret IDs or a filter, an attacker may use a catch-all filter to retrieve all secrets by batch:

```json hl_lines="6-11"
{
  "eventSource": "secretsmanager.amazonaws.com",
  "eventName": "BatchGetSecretValue",
  "requestParameters": {
    "filters": [
      {
        "key": "tag-key",
        "values": [
          "!tagKeyThatWillNeverExist"
        ]
      }
    ]
  },
  "responseElements": null,
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "012345678901"
}
```

The following may be use to tune the detection, or validate findings:

- Principals who do not usually call GetBatchSecretValue
- Attempts to call GetBatchSecretValue resulting in access denied errors
- Principals calling GetBatchSecretValue in several regions in a short period of time




## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `secretsmanager:BatchGetSecretValue`


??? "View raw detonation logs"

    ```json hl_lines="6 46 86 126 166"

    [
	   {
	      "awsRegion": "eu-westwest-1r",
	      "eventCategory": "Management",
	      "eventID": "61619dbf-c10b-471e-9d78-8199a2f8233a",
	      "eventName": "BatchGetSecretValue",
	      "eventSource": "secretsmanager.amazonaws.com",
	      "eventTime": "2024-07-31T12:29:17Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "165109126369",
	      "requestID": "d493c657-4004-4105-81f0-8f468ba0c9b3",
	      "requestParameters": {
	         "filters": [
	            {
	               "key": "tag-key",
	               "values": [
	                  "StratusRedTeam"
	               ]
	            }
	         ]
	      },
	      "responseElements": null,
	      "sourceIPAddress": "88.223.251.255",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "secretsmanager.eu-westwest-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_0a05817a-84d2-40d7-afde-8311715b1ee6",
	      "userIdentity": {
	         "accessKeyId": "AKIALK3Q0HKBKZJ2XBYP",
	         "accountId": "165109126369",
	         "arn": "arn:aws:iam::165109126369:user/christophe",
	         "principalId": "AIDAIOBKTJ7YOYY9TKC4",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "eu-westwest-1r",
	      "eventCategory": "Management",
	      "eventID": "7c7a69f9-867d-4b5b-beee-7fe62ba34d5c",
	      "eventName": "BatchGetSecretValue",
	      "eventSource": "secretsmanager.amazonaws.com",
	      "eventTime": "2024-07-31T12:29:17Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "165109126369",
	      "requestID": "6b6e2935-39ad-44d9-9a62-eeb63e95bd69",
	      "requestParameters": {
	         "filters": [
	            {
	               "key": "tag-key",
	               "values": [
	                  "StratusRedTeam"
	               ]
	            }
	         ]
	      },
	      "responseElements": null,
	      "sourceIPAddress": "88.223.251.255",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "secretsmanager.eu-westwest-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_0a05817a-84d2-40d7-afde-8311715b1ee6",
	      "userIdentity": {
	         "accessKeyId": "AKIALK3Q0HKBKZJ2XBYP",
	         "accountId": "165109126369",
	         "arn": "arn:aws:iam::165109126369:user/christophe",
	         "principalId": "AIDAIOBKTJ7YOYY9TKC4",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "eu-westwest-1r",
	      "eventCategory": "Management",
	      "eventID": "cf4e352a-b575-4003-bd81-0c531f42e626",
	      "eventName": "BatchGetSecretValue",
	      "eventSource": "secretsmanager.amazonaws.com",
	      "eventTime": "2024-07-31T12:29:17Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "165109126369",
	      "requestID": "cd93c41b-cb19-4a2c-9f35-6a1becee24ce",
	      "requestParameters": {
	         "filters": [
	            {
	               "key": "tag-key",
	               "values": [
	                  "StratusRedTeam"
	               ]
	            }
	         ]
	      },
	      "responseElements": null,
	      "sourceIPAddress": "88.223.251.255",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "secretsmanager.eu-westwest-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_0a05817a-84d2-40d7-afde-8311715b1ee6",
	      "userIdentity": {
	         "accessKeyId": "AKIALK3Q0HKBKZJ2XBYP",
	         "accountId": "165109126369",
	         "arn": "arn:aws:iam::165109126369:user/christophe",
	         "principalId": "AIDAIOBKTJ7YOYY9TKC4",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "eu-westwest-1r",
	      "eventCategory": "Management",
	      "eventID": "bddee0fb-2541-430d-aad5-b1fdd5d419f1",
	      "eventName": "BatchGetSecretValue",
	      "eventSource": "secretsmanager.amazonaws.com",
	      "eventTime": "2024-07-31T12:29:16Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "165109126369",
	      "requestID": "6bd1a472-24d2-46b5-abb6-83a9caf3e3ea",
	      "requestParameters": {
	         "filters": [
	            {
	               "key": "tag-key",
	               "values": [
	                  "StratusRedTeam"
	               ]
	            }
	         ]
	      },
	      "responseElements": null,
	      "sourceIPAddress": "88.223.251.255",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "secretsmanager.eu-westwest-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_0a05817a-84d2-40d7-afde-8311715b1ee6",
	      "userIdentity": {
	         "accessKeyId": "AKIALK3Q0HKBKZJ2XBYP",
	         "accountId": "165109126369",
	         "arn": "arn:aws:iam::165109126369:user/christophe",
	         "principalId": "AIDAIOBKTJ7YOYY9TKC4",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "eu-westwest-1r",
	      "eventCategory": "Management",
	      "eventID": "cdc49957-9518-4ab3-a49e-b5a7c17903e6",
	      "eventName": "BatchGetSecretValue",
	      "eventSource": "secretsmanager.amazonaws.com",
	      "eventTime": "2024-07-31T12:29:16Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "165109126369",
	      "requestID": "be2e79d0-ef1a-47f1-90b4-bafbbaa7404c",
	      "requestParameters": {
	         "filters": [
	            {
	               "key": "tag-key",
	               "values": [
	                  "StratusRedTeam"
	               ]
	            }
	         ]
	      },
	      "responseElements": null,
	      "sourceIPAddress": "88.223.251.255",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "secretsmanager.eu-westwest-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_0a05817a-84d2-40d7-afde-8311715b1ee6",
	      "userIdentity": {
	         "accessKeyId": "AKIALK3Q0HKBKZJ2XBYP",
	         "accountId": "165109126369",
	         "arn": "arn:aws:iam::165109126369:user/christophe",
	         "principalId": "AIDAIOBKTJ7YOYY9TKC4",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
