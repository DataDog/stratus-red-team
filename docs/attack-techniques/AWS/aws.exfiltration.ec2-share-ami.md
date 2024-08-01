---
title: Exfiltrate an AMI by Sharing It
---

# Exfiltrate an AMI by Sharing It


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates an AMI by sharing it with an external AWS account.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an AMI.

<span style="font-variant: small-caps;">Detonation</span>: 

- Share the AMI with an external, fictitious AWS account.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.ec2-share-ami
```
## Detection


Through CloudTrail's <code>ModifyImageAttribute</code> event, when <code>requestParameters.launchPermission</code> shows
that the AMI was shared with a new or unknown AWS account, such as:

<pre><code>"requestParameters": {
  "launchPermission": {
    "add": {
	  "items": [{ "userId": "012345678901" }]
    }
  },
  "attributeType": "launchPermission",
  "imageId": "ami-0b87ea1d007078d18"
}</code></pre>

An attacker can also make an AMI completely public. In this case, the <code>item</code> entry 
will look like <code>{"groups":"all"}</code>. 



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `ec2:ModifyImageAttribute`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "me-south-1r",
	      "eventCategory": "Management",
	      "eventID": "1f00bcfa-e050-4c2e-b99b-768ebe3a3dd3",
	      "eventName": "ModifyImageAttribute",
	      "eventSource": "ec2.amazonaws.com",
	      "eventTime": "2024-08-01T12:25:57Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "118238665043",
	      "requestID": "dd81ae39-a261-4e85-87a4-01fe22abc602",
	      "requestParameters": {
	         "attributeType": "launchPermission",
	         "imageId": "ami-de1fbCab6ccB03e6D",
	         "launchPermission": {
	            "add": {
	               "items": [
	                  {
	                     "userId": "846424999548"
	                  }
	               ]
	            }
	         }
	      },
	      "responseElements": {
	         "_return": true,
	         "requestId": "dd81ae39-a261-4e85-87a4-01fe22abc602"
	      },
	      "sourceIPAddress": "253.19.58.252",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2.me-south-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_a532baf6-7731-4c0f-b089-48508276f787",
	      "userIdentity": {
	         "accessKeyId": "AKIA40XZ2OQU8R4QKTAC",
	         "accountId": "118238665043",
	         "arn": "arn:aws:iam::118238665043:user/christophe",
	         "principalId": "AIDAYO61EC4B4W5G6BXN",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
