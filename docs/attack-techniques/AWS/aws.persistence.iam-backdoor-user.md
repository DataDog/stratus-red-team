---
title: Create an Access Key on an IAM User
---

# Create an Access Key on an IAM User




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating an access key on an existing IAM user.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an IAM user.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create an IAM access key on the user.

References:

- https://sysdig.com/blog/scarleteel-2-0/
- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-backdoor-user
```
## Detection


Through CloudTrail's <code>CreateAccessKey</code> event. This event can hardly be considered suspicious by itself, unless
correlated with other indicators.
'


## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `iam:CreateAccessKey`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "ap-central-2r",
	      "eventCategory": "Management",
	      "eventID": "c64c4ded-ef03-4e5c-81eb-153b118d72f2",
	      "eventName": "CreateAccessKey",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-07-30T21:53:13Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "946986569305",
	      "requestID": "1af58177-d743-4c94-ac1d-014721ed9b94",
	      "requestParameters": {
	         "userName": "stratus-red-team-backdoor-u-user"
	      },
	      "responseElements": {
	         "accessKey": {
	            "accessKeyId": "AKIAL80DWDVKKM0UXEER",
	            "createDate": "Jul 30, 2024 9:53:13 PM",
	            "status": "Active",
	            "userName": "stratus-red-team-backdoor-u-user"
	         }
	      },
	      "sourceIPAddress": "211.9.016.253",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_f3f19dcd-8552-47ca-a01e-0e1f5578d15e",
	      "userIdentity": {
	         "accessKeyId": "AKIA30BEZSJBVKOFKZW0",
	         "accountId": "946986569305",
	         "arn": "arn:aws:iam::946986569305:user/christophe",
	         "principalId": "AIDAKYRO1QIPZ5M62HCS",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
