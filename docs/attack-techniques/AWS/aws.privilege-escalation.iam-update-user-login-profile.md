---
title: Change IAM user password
---

# Change IAM user password


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Privilege Escalation

## Description


Establishes persistence by updating a Login Profile on an existing IAM user to change its password. This allows an attacker to hijack 
an IAM user with an existing login profile.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM user with a login profile

<span style="font-variant: small-caps;">Detonation</span>: 

- Update the user's login profile to change its password

References:

- https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me
- https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/
- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.privilege-escalation.iam-update-user-login-profile
```
## Detection


Through CloudTrail's <code>UpdateLoginProfile</code> events.



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `iam:UpdateLoginProfile`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "megov-southcentral-3r",
	      "eventCategory": "Management",
	      "eventID": "a46a1a42-9ef1-48d4-9c61-507eb6d4019f",
	      "eventName": "UpdateLoginProfile",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-28T09:54:40Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "763751499319",
	      "requestID": "bd8967e5-b80d-48cd-b8b5-45c9905a4a7f",
	      "requestParameters": {
	         "userName": "stratus-red-team-update-login-profile-user"
	      },
	      "responseElements": null,
	      "sourceIPAddress": "212.3.253.233",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_33d1bcd6-0716-4e7f-a145-8a75625cf180",
	      "userIdentity": {
	         "accessKeyId": "AKIAV1MIS7NGMDMR83FC",
	         "accountId": "763751499319",
	         "arn": "arn:aws:iam::763751499319:user/christophe",
	         "principalId": "AIDAXYBG3LDVX65FGD9O",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
