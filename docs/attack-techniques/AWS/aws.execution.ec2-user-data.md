---
title: Execute Commands on EC2 Instance via User Data
---

# Execute Commands on EC2 Instance via User Data

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Execution
- Privilege Escalation

## Description


Executes code on a Linux EC2 instance through User Data.

References:

- https://hackingthe.cloud/aws/exploitation/local-priv-esc-mod-instance-att/
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html

<span style="font-variant: small-caps;">Warm-up</span>:

- Create the prerequisite EC2 instance and VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>:

- Stop the instance
- Use ModifyInstanceAttribute to inject a malicious script in user data
- Start the instance
- Upon starting, the malicious script in user data is automatically executed as the root user


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.execution.ec2-user-data
```
## Detection


Identify when the following sequence of CloudTrail events occur in a short period of time (e.g., < 1 hour)

1. <code>StopInstances</code> (necessary, because the user data of an instance cannot be changed when it's running)
2. <code>ModifyInstanceAttribute</code> with <code>requestParameters.userData</code> non-empty

When not possible to perform such correlation, alerting on the second event only is an option. It's generally not 
expected that the user data of an EC2 instance changes often, especially with the popularity of immutable machine images,
provisioned before instantiation.



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `ssm:DescribeParameters`

- `ssm:GetParameters`


??? "View raw detonation logs"

    ```json hl_lines="6 40 74 161 248 282 369 456 490 537"

    [
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "3c83144c-614c-4979-ad06-b29d4db97c45",
	      "eventName": "DescribeParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:57Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "13846448-4620-4f7a-af9f-f3e8bb7331e4",
	      "requestParameters": {
	         "maxResults": 10,
	         "nextToken": "AAEAAWTrG1XzfC+I+cBZdv2e1Y6JxbMPL7ueqKuvIWVzlNmJAAAAAGarqUEtel9rb1/hWoLuU2fulBaFOAdkVl/mZEj6gahZa13rY/NLTIYY7M5dJzOP+lpBWs4Xs9bGXKBNkSuXRdpmHac6HKafIoo/QaeZdw3phYjDbq+RQR7saxp5c/bOWIMtNBYD/A/sd4cnb/986qFM4978kxcqKsA1KSpCzNL187ypwamchw+ENE8Jk6ZLCTv3edGWlUGFZRVIH1Owq+e597P7xLkwkIQHvn8uNFeW7tW6/SNukEbMkSiyJ/0XMXTytqj4Buns0LSigHLelswkOBTE8NZ3aQM1EFjlTl8Lq6LS5Lsv813z4yv1Qo1Wn8iAUhJ72IsTLpYsWnQNAl7smhlKga0N06ueI7CQErvWfHLNR+BsA5U6XJ3KReNmwRHc47BfR7Xo4ibktKGlGCabtUe9X09W7W2X6NtJv/Q3s4ArEczKQk0e3qEx49nZYLmHQs8BJn7QWgATgAAqUWB1bBEKq2NKNFdHNc2P+N4sypbANg8dVi/+fCRZ6JgDom5r/LXSB+lxThU6i4yiCb1EB6kzPXKME2FqeRm2oH+n4KT2qDX9WW5qxNIvSYbHKcPbtxGbZHBZiVdgjQdDxSkc8qCAPQ5cedA18AJ6gQy6sNl/zgs1ILAUErFz6QaWhozFU0FZiBCK6aiNA5czIPIlDld3+DrTKmuf46PmUg/iJym2zQ=="
	      },
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "a16d52e1-5e70-44da-b1bd-9016cd1b1cb0",
	      "eventName": "DescribeParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:57Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "a94ac3e5-6956-4bd4-ae7a-6c4517865b56",
	      "requestParameters": {
	         "maxResults": 10,
	         "nextToken": "AAEAAfqeTJBa9KzNy85Z/I9fugPDwcPX+6UgaeHcuXfK5NcfAAAAAGarqUAd2tcUDuJEuPOIEBFqxxAR2+Ls88vLJSSWVsgnhZkVpRH+/ddn7uN8ec0Gr584BOjtFxs2RNVM/BPT/Ka52SNZS8C4jsMXbFQyAIJCEVCy8oL+v+i5Sxfvn/fKNmLSNj8oci/vsGBMkPwPd1/3juDlgjoqjsMUTHJv+HVDfMuVm9bRqXO+FyUFppOpaqsZOfrKPumVN5p+Pa2QcTVQlegs72EzvnCarJYmoI63g5PmxWE9jhgs24rSTdm7oX6Ai4hYjGmhtZoIrFU/JGumeM7X0rivOEMRVAX//LKs+78Zyt2sPFMHFfEu7tqarKcMQDEP164enW/bwuOT+X0cn6ps1eyaQJyFQoMACCMRYDlZ0kn5c9LnQ5HqmimQnRIes6y+7CXHIhbV0ZZBsIdqXiGcPy4X7+s2VPJMq+2CTdPsmkQs0JS/p+y6PoN+k92S/HTGZpUqOBd59dT+mBmpLvCeBYoskxKZPuc/j84po9DZGsVNPRKHzqhsH5p9m9oSc+ZnEAF571cZmXM56I0BtSScsWP14HtZEEAwwV3batz4uKXbw7cHPRgBbyNVg3y6X0tjrgyk2/MD9BNlOTgrRHIJ1CAV9OQNY0WK+Y4KhXLkqebum6qTY+ijqrpwoHgsc9yXjxMxXFsZoutMiBYUWv7z22w32l3I9xXExJrU10oy8A=="
	      },
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "a4663305-e887-42ac-94e6-d04685e59899",
	      "eventName": "GetParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:57Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "be330b1c-725a-49bc-bac2-8d0d114c7e73",
	      "requestParameters": {
	         "names": [
	            "/credentials/stratus-red-team/credentials-1",
	            "/credentials/stratus-red-team/credentials-15",
	            "/credentials/stratus-red-team/credentials-20",
	            "/credentials/stratus-red-team/credentials-25",
	            "/credentials/stratus-red-team/credentials-32",
	            "/credentials/stratus-red-team/credentials-34",
	            "/credentials/stratus-red-team/credentials-35",
	            "/credentials/stratus-red-team/credentials-36",
	            "/credentials/stratus-red-team/credentials-39",
	            "/credentials/stratus-red-team/credentials-6"
	         ],
	         "withDecryption": true
	      },
	      "resources": [
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-1",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-15",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-20",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-25",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-32",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-34",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-35",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-36",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-39",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-6",
	            "accountId": "605371824065"
	         }
	      ],
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "f7fd8826-9ac0-46a5-b7d5-55c269f59541",
	      "eventName": "GetParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:57Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "4bd8d56f-70f4-4b29-8702-b517ee503852",
	      "requestParameters": {
	         "names": [
	            "/credentials/stratus-red-team/credentials-11",
	            "/credentials/stratus-red-team/credentials-17",
	            "/credentials/stratus-red-team/credentials-18",
	            "/credentials/stratus-red-team/credentials-22",
	            "/credentials/stratus-red-team/credentials-26",
	            "/credentials/stratus-red-team/credentials-3",
	            "/credentials/stratus-red-team/credentials-31",
	            "/credentials/stratus-red-team/credentials-37",
	            "/credentials/stratus-red-team/credentials-38",
	            "/credentials/stratus-red-team/credentials-7"
	         ],
	         "withDecryption": true
	      },
	      "resources": [
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-11",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-17",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-18",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-22",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-26",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-3",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-31",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-37",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-38",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-7",
	            "accountId": "605371824065"
	         }
	      ],
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "674e3606-412b-4468-8d97-df54a290c564",
	      "eventName": "DescribeParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:56Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "76e5cae2-768a-4fce-a2d2-b162e27c8293",
	      "requestParameters": {
	         "maxResults": 10,
	         "nextToken": "AAEAAYl+RRW68eJ0xW6biiQkM0UFbgLzAw680L15/s+wHzuWAAAAAGarqT8yLEDnasB3CYBlA/iBSdCHG6jmIVUUgyWN6FIuTR9LfGXxx5xnVpiuEeGOELVuVJR35ZqhwXSVIiS57kfs3KUyffu+H0Iy3PYS9EztV7mH58Q3pE5jcU13IozWkd03XYMkAl2hgz5xX2g3SW8BGD2QeBUYmtHspZrSSpDloZoeJ+DCcQPwHRc9NjbnOnscO8TFqWvos2OmRpMtyA5BY1UAtBwkd9A6C4k2+97cBtu71URXDkT4wP4DeSPM/ZgSnZudGylYxUP7cZPwcK/uxr6cw/ihqQ7B30xIdIt9a1k81WBsCeV5KdBTXQHyUEQxMQd4uEZD1nEd30nsg+JtHF5ckuYS19zYoNCKydCr2aFg7/dNCdrZy0hvmJ+bw/QESYs8ZUMj4i7ilDoVo/I+RXQogojGBVnVES0wxCidKLyDQBDxAYur9eL4fwbstwdeFJJTP1vr822DvXDs0Q5l0P590bEanMD5ZdC/+kVkOO2LdAHfRXe8Osb6tua7PsvLpm9DYs7jjJ7gZciC18XxygX5d77FpIw4LtiDvFKrtzIjhmy6ZOKfxaDjYUlpJ5trxawf5FX0jQuLSYw0HMsZEv9tU0iVVvCGcJPPuX0V2jR8vCbUUJe1LFnROuBDkcpvfsSIcD+jV3caD14QlsFP0oT5pdi8iE4lQQs42UBpfDxMHA=="
	      },
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "7fbcfbae-35c6-4c93-88bf-741fe4c4ada3",
	      "eventName": "GetParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:56Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "879a4957-60a5-413d-be00-de67325a9f33",
	      "requestParameters": {
	         "names": [
	            "/credentials/stratus-red-team/credentials-10",
	            "/credentials/stratus-red-team/credentials-13",
	            "/credentials/stratus-red-team/credentials-14",
	            "/credentials/stratus-red-team/credentials-2",
	            "/credentials/stratus-red-team/credentials-23",
	            "/credentials/stratus-red-team/credentials-27",
	            "/credentials/stratus-red-team/credentials-29",
	            "/credentials/stratus-red-team/credentials-33",
	            "/credentials/stratus-red-team/credentials-4",
	            "/credentials/stratus-red-team/credentials-41"
	         ],
	         "withDecryption": true
	      },
	      "resources": [
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-10",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-13",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-14",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-2",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-23",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-27",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-29",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-33",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-4",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-41",
	            "accountId": "605371824065"
	         }
	      ],
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "d487c732-d152-48b1-9897-90b3a037040d",
	      "eventName": "GetParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:56Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "b93b1643-c5ab-4c02-90d3-4bfa619ca186",
	      "requestParameters": {
	         "names": [
	            "/credentials/stratus-red-team/credentials-0",
	            "/credentials/stratus-red-team/credentials-16",
	            "/credentials/stratus-red-team/credentials-19",
	            "/credentials/stratus-red-team/credentials-21",
	            "/credentials/stratus-red-team/credentials-24",
	            "/credentials/stratus-red-team/credentials-28",
	            "/credentials/stratus-red-team/credentials-30",
	            "/credentials/stratus-red-team/credentials-5",
	            "/credentials/stratus-red-team/credentials-8",
	            "/credentials/stratus-red-team/credentials-9"
	         ],
	         "withDecryption": true
	      },
	      "resources": [
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-0",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-16",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-19",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-21",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-24",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-28",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-30",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-5",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-8",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-9",
	            "accountId": "605371824065"
	         }
	      ],
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "f1283a09-788f-4b20-8b4f-0364dce2968a",
	      "eventName": "DescribeParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:56Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "48e17307-1cde-4161-8e06-322fa6e2aef0",
	      "requestParameters": {
	         "maxResults": 10,
	         "nextToken": "AAEAAaBteYGa8oU2QyrYeGJUO62kbtV8jAxUkBelmma5CqZTAAAAAGarqUCgxn/Ts/JpI10tWTxO0Tx6RGC9jR11wb7NoHX+2QDw8Ae6WOTrT/drS4ppinCT5SowtU1Tislk2nW5dyonFkinraADtk6zT6QQoDzl07aHweO32RmyFBre/v7j5Dx4RFEgqNARuE5AjxUT7+8V1CEvdisL+PlTYWA25MtdB4/sclYzUPL3Hdr6wTrmTsvvOZMCkHsV6Ug4sSh00zcNOI16NuXkSWC4yTPvJYvaxZiyp9KxkHsp38YDbY/UiKo2ijIouBErXOdGhMRn8FsK9iu2L2KAPXRLpdfihaWSujZBMEMuPgk+m/FmwkoYMEFpp/nRyOEZQjRBKCsRNIb4LJG5NXUR7vQXoa4fkXyctEwl4osDP5HN/4rH8A5DxRC25CKGMKr24mc7KYVbNvYOiCxSFD4LowdsesAKIzpq66ta7prMnAXJGTH+NauLkTXeXDhpuxtGtQuqGGjN3E2uZ+8xQSJ7/jzZMbO3UGMwxvdedgWjf53SQ8qgmXEzjs1aXxKuzefv+Of44HG3deLlSlLWU1G2Age9WJRjG90QYdxD+xJjhiCaGH83gypzZWwMuRFg6rmYAPn5Q+pan1HJYU9BFxZKYC9ZPP+4bOab7RjTn7Kt1tEkFiVCXR2HjD2P6pP7oPd/tORQYwpd4Boi8+VS2QH1oxEOhROHeVkPvpRGnw=="
	      },
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "fb5e100b-273f-4cef-98e4-efc3a52a15e9",
	      "eventName": "GetParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:58Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "760b9a37-2498-4d32-b041-f153827bcc3e",
	      "requestParameters": {
	         "names": [
	            "/credentials/stratus-red-team/credentials-12",
	            "/credentials/stratus-red-team/credentials-40"
	         ],
	         "withDecryption": true
	      },
	      "resources": [
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-12",
	            "accountId": "605371824065"
	         },
	         {
	            "ARN": "arn:aws:ssm:sa-isob-west-2r:605371824065:parameter/credentials/stratus-red-team/credentials-40",
	            "accountId": "605371824065"
	         }
	      ],
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "sa-isob-west-2r",
	      "eventCategory": "Management",
	      "eventID": "e77574ca-5c4f-4d99-9f3d-67cbfd04aa99",
	      "eventName": "DescribeParameters",
	      "eventSource": "ssm.amazonaws.com",
	      "eventTime": "2024-08-01T15:26:55Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": true,
	      "recipientAccountId": "605371824065",
	      "requestID": "7f54e3af-2dc7-4392-8d7c-9a7f018dd1a2",
	      "requestParameters": {
	         "maxResults": 10
	      },
	      "responseElements": null,
	      "sourceIPAddress": "206.8.213.255",
	      "tlsDetails": {
	         "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
	         "clientProvidedHostHeader": "ssm.sa-isob-west-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.2"
	      },
	      "userAgent": "stratus-red-team_e1d92b9d-2488-4244-97b4-0a5e914287ba",
	      "userIdentity": {
	         "accessKeyId": "AKIA8P60BVPKXO7EASQX",
	         "accountId": "605371824065",
	         "arn": "arn:aws:iam::605371824065:user/christophe",
	         "principalId": "AIDA3V1QQIO0DYD2QRMD",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
