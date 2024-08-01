---
title: Create an administrative IAM User
---

# Create an administrative IAM User




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a new IAM user with administrative permissions.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create the IAM user and attach the 'AdministratorAccess' managed IAM policy to it.

References:

- https://permiso.io/blog/s/approach-to-detection-androxgh0st-greenbot-persistence/
- https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/
- https://blog.darklab.hk/2021/07/06/trouble-in-paradise/
- https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-create-admin-user
```
## Detection


Through CloudTrail's <code>CreateUser</code>, <code>AttachUserPolicy</code> and <code>CreateAccessKey</code> events.

While matching on these events may be impractical and prone to false positives in most environments, the following
can help to craft more precise detections:

- Identify a call to <code>CreateUser</code> closely followed by <code>AttachUserPolicy</code> with an administrator policy.

- Identify a call to <code>CreateUser</code> resulting in an access denied error.





## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `iam:CreateAccessKey`

- `iam:CreateUser`

- `iam:AttachUserPolicy`


??? "View raw detonation logs"

    ```json hl_lines="6 40 80"

    [
	   {
	      "awsRegion": "ap-isob-central-3r",
	      "eventCategory": "Management",
	      "eventID": "083dc4ad-e264-46bc-a407-d0dd31b58bdc",
	      "eventName": "AttachUserPolicy",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-01T13:33:28Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "229654561268",
	      "requestID": "710f2703-6e8a-46d5-9924-b12a3a681755",
	      "requestParameters": {
	         "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
	         "userName": "malicious-iam-user"
	      },
	      "responseElements": null,
	      "sourceIPAddress": "075.050.255.67",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_6bf00313-712c-4fd2-9bdd-88f48a4b1282",
	      "userIdentity": {
	         "accessKeyId": "AKIAOZUDECYXYM4ONAN4",
	         "accountId": "229654561268",
	         "arn": "arn:aws:iam::229654561268:user/christophe",
	         "principalId": "AIDAZ49AHUAJ9OEK73O5",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "ap-isob-central-3r",
	      "eventCategory": "Management",
	      "eventID": "94faedcc-0fa4-46e6-9322-022e8e934f04",
	      "eventName": "CreateAccessKey",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-01T13:33:28Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "229654561268",
	      "requestID": "0ee5fc85-66bb-4602-a69e-9a5a2a3add30",
	      "requestParameters": {
	         "userName": "malicious-iam-user"
	      },
	      "responseElements": {
	         "accessKey": {
	            "accessKeyId": "AKIAXAFZN8JEPF6L682H",
	            "createDate": "Aug 1, 2024 1:33:28 PM",
	            "status": "Active",
	            "userName": "malicious-iam-user"
	         }
	      },
	      "sourceIPAddress": "075.050.255.67",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_6bf00313-712c-4fd2-9bdd-88f48a4b1282",
	      "userIdentity": {
	         "accessKeyId": "AKIAOZUDECYXYM4ONAN4",
	         "accountId": "229654561268",
	         "arn": "arn:aws:iam::229654561268:user/christophe",
	         "principalId": "AIDAZ49AHUAJ9OEK73O5",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "ap-isob-central-3r",
	      "eventCategory": "Management",
	      "eventID": "3346344c-5a3e-429e-8405-420f98f75d6e",
	      "eventName": "CreateUser",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-01T13:33:28Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "229654561268",
	      "requestID": "64ef9c47-6b64-4c0e-8c32-eb9ffaf8a658",
	      "requestParameters": {
	         "tags": [
	            {
	               "key": "StratusRedTeam",
	               "value": "true"
	            }
	         ],
	         "userName": "malicious-iam-user"
	      },
	      "responseElements": {
	         "user": {
	            "arn": "arn:aws:iam::229654561268:user/malicious-iam-user",
	            "createDate": "Aug 1, 2024 1:33:28 PM",
	            "path": "/",
	            "tags": [
	               {
	                  "key": "StratusRedTeam",
	                  "value": "true"
	               }
	            ],
	            "userId": "AIDAL1XMLVWIUOK8KAF0",
	            "userName": "malicious-iam-user"
	         }
	      },
	      "sourceIPAddress": "075.050.255.67",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_6bf00313-712c-4fd2-9bdd-88f48a4b1282",
	      "userIdentity": {
	         "accessKeyId": "AKIAOZUDECYXYM4ONAN4",
	         "accountId": "229654561268",
	         "arn": "arn:aws:iam::229654561268:user/christophe",
	         "principalId": "AIDAZ49AHUAJ9OEK73O5",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
