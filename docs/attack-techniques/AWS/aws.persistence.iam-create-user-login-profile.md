---
title: Create a Login Profile on an IAM User
---

# Create a Login Profile on an IAM User




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a Login Profile on an existing IAM user. This allows an attacker to access an IAM
user intended to be used programmatically through the AWS console usual login process. 

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM user

<span style="font-variant: small-caps;">Detonation</span>: 

- Create an IAM Login Profile on the user

References:

- https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/
- https://permiso.io/blog/s/approach-to-detection-androxgh0st-greenbot-persistence/
- https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/
- https://blog.darklab.hk/2021/07/06/trouble-in-paradise/
- https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/
- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-create-user-login-profile
```
## Detection


Through CloudTrail's <code>CreateLoginProfile</code> or <code>UpdateLoginProfile</code> events.

In particular, it's suspicious when these events occur on IAM users intended to be used programmatically.



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `sts:GetCallerIdentity`

- `iam:DeleteLoginProfile`

- `iam:CreateLoginProfile`


??? "View raw detonation logs"

    ```json hl_lines="6 39 72"

    [
	   {
	      "awsRegion": "ap-central-2r",
	      "eventCategory": "Management",
	      "eventID": "e544d47e-6d75-45cf-a8a9-7e90d5f7d38d",
	      "eventName": "GetCallerIdentity",
	      "eventSource": "sts.amazonaws.com",
	      "eventTime": "2024-08-01T13:42:21Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "070411556318",
	      "requestID": "8a4782c5-408f-4ff4-be0b-6e10202f385f",
	      "requestParameters": null,
	      "responseElements": null,
	      "sourceIPAddress": "253.234.5.234",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "sts.ap-central-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_99dfa7e5-00d3-40b7-8cfd-b2573ada0eac",
	      "userIdentity": {
	         "accessKeyId": "AKIAE18PGYHCY2CYMTFK",
	         "accountId": "070411556318",
	         "arn": "arn:aws:iam::070411556318:user/christophe",
	         "principalId": "AIDAWVCXQ27A1H7FID62",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "ap-central-2r",
	      "errorCode": "EntityTemporarilyUnmodifiableException",
	      "errorMessage": "Login Profile for User stratus-red-team-login-profile-user cannot be modified while login profile is being created.",
	      "eventCategory": "Management",
	      "eventID": "64fb98c9-cb40-4f9a-b800-6c15e82e9be6",
	      "eventName": "DeleteLoginProfile",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-01T13:42:22Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "070411556318",
	      "requestID": "a0953f02-9f5f-408a-8188-427026ef914b",
	      "requestParameters": {
	         "userName": "stratus-red-team-login-profile-user"
	      },
	      "responseElements": null,
	      "sourceIPAddress": "253.234.5.234",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_99dfa7e5-00d3-40b7-8cfd-b2573ada0eac",
	      "userIdentity": {
	         "accessKeyId": "AKIAE18PGYHCY2CYMTFK",
	         "accountId": "070411556318",
	         "arn": "arn:aws:iam::070411556318:user/christophe",
	         "principalId": "AIDAWVCXQ27A1H7FID62",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "ap-central-2r",
	      "eventCategory": "Management",
	      "eventID": "d3906a7d-604b-407f-acb6-fc425742821e",
	      "eventName": "CreateLoginProfile",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-01T13:42:21Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "070411556318",
	      "requestID": "cb603f7a-02cc-4123-9855-658655364408",
	      "requestParameters": {
	         "passwordResetRequired": false,
	         "userName": "stratus-red-team-login-profile-user"
	      },
	      "responseElements": {
	         "loginProfile": {
	            "createDate": "Aug 1, 2024 1:42:21 PM",
	            "passwordResetRequired": false,
	            "userName": "stratus-red-team-login-profile-user"
	         }
	      },
	      "sourceIPAddress": "253.234.5.234",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_99dfa7e5-00d3-40b7-8cfd-b2573ada0eac",
	      "userIdentity": {
	         "accessKeyId": "AKIAE18PGYHCY2CYMTFK",
	         "accountId": "070411556318",
	         "arn": "arn:aws:iam::070411556318:user/christophe",
	         "principalId": "AIDAWVCXQ27A1H7FID62",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
