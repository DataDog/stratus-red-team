---
title: Usage of EC2 Serial Console to push SSH public key
---

# Usage of EC2 Serial Console to push SSH public key

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Lateral Movement

## Description


Simulates an attacker using EC2 Instance Connect to push an SSH public key to multiple EC2 instances, using <code>SendSerialConsoleSSHPublicKey</code>. This allows anyone 
with the corresponding private key to connect directly to the systems via SSH, assuming they have appropriate network connectivity.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create multiple EC2 instances and a VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>:

- Adds a public SSH key to the EC2 instances using <code>SendSerialConsoleSSHPublicKey</code>.

References:

- https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/API_SendSerialConsoleSSHPublicKey.html
- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
- https://fwdcloudsec.org/assets/presentations/2024/europe/sebastian-walla-cloud-conscious-tactics-techniques-and-procedures-an-overview.pdf
- https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/
- https://unit42.paloaltonetworks.com/cloud-virtual-machine-attack-vectors/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.lateral-movement.ec2-serial-console-send-ssh-public-key
```
## Detection


Identify, through CloudTrail's <code>SendSerialConsoleSSHPublicKey</code> event, when a user is adding an SSH key to EC2 instances.



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `ec2-instance-connect:SendSerialConsoleSSHPublicKey`

- `ec2:EnableSerialConsoleAccess`


??? "View raw detonation logs"

    ```json hl_lines="6 57 109 161"

    [
	   {
	      "awsRegion": "cniso-east-3r",
	      "eventCategory": "Management",
	      "eventID": "37ba412b-f943-44f2-ae48-4527f6e789d9",
	      "eventName": "EnableSerialConsoleAccess",
	      "eventSource": "ec2.amazonaws.com",
	      "eventTime": "2024-11-26T15:35:22Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.10",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "844015365555",
	      "requestID": "e110338f-cc06-4284-bf16-6528a7df1561",
	      "requestParameters": {
	         "EnableSerialConsoleAccessRequest": ""
	      },
	      "responseElements": {
	         "EnableSerialConsoleAccessResponse": {
	            "requestId": "e110338f-cc06-4284-bf16-6528a7df1561",
	            "serialConsoleAccessEnabled": true,
	            "xmlns": "http://ec2.amazonaws.com/doc/2016-11-15/"
	         }
	      },
	      "sourceIPAddress": "201.252.42.03",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2.cniso-east-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_b0fedc91-bd4a-4ba1-a776-80e707fef2a0",
	      "userIdentity": {
	         "accessKeyId": "ASIA2HJRQF0DHNYEE9N1",
	         "accountId": "844015365555",
	         "arn": "arn:aws:sts::844015365555:assumed-role/AWSReservedSSOrandoml3I7nL6f7BmB@gmail.com",
	         "principalId": "AROAEMHZD694LU95MUYOP:randomca0L529zwNAY@gmail.com",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-11-26T15:14:58Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "844015365555",
	               "arn": "arn:aws:iam::844015365555:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_account-admin_599c9e90e350d2ff",
	               "principalId": "AROAEMHZD694LU95MUYOP",
	               "type": "Role",
	               "userName": "AWSReservedSSO_account-admin_599c9e90e350d2ff"
	            }
	         },
	         "type": "AssumedRole"
	      }
	   },
	   {
	      "awsRegion": "cniso-east-3r",
	      "eventCategory": "Management",
	      "eventID": "787b2464-f27b-4d4c-91bc-6396f2297d0e",
	      "eventName": "SendSerialConsoleSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-11-26T15:35:23Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "844015365555",
	      "requestID": "c74b1e77-bc91-4174-b297-d06a71c89abf",
	      "requestParameters": {
	         "instanceId": "i-EFCb4e480CAbc4CF9",
	         "monitorMode": false,
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu",
	         "serialPort": 0
	      },
	      "responseElements": {
	         "requestId": "c74b1e77-bc91-4174-b297-d06a71c89abf",
	         "success": true
	      },
	      "sourceIPAddress": "201.252.42.03",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.cniso-east-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_b0fedc91-bd4a-4ba1-a776-80e707fef2a0",
	      "userIdentity": {
	         "accessKeyId": "ASIA2HJRQF0DHNYEE9N1",
	         "accountId": "844015365555",
	         "arn": "arn:aws:sts::844015365555:assumed-role/AWSReservedSSOrandoml3I7nL6f7BmB@gmail.com",
	         "principalId": "AROAEMHZD694LU95MUYOP:randomca0L529zwNAY@gmail.com",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-11-26T15:14:58Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "844015365555",
	               "arn": "arn:aws:iam::844015365555:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_account-admin_599c9e90e350d2ff",
	               "principalId": "AROAEMHZD694LU95MUYOP",
	               "type": "Role",
	               "userName": "AWSReservedSSO_account-admin_599c9e90e350d2ff"
	            },
	            "webIdFederationData": {}
	         },
	         "type": "AssumedRole"
	      }
	   },
	   {
	      "awsRegion": "cniso-east-3r",
	      "eventCategory": "Management",
	      "eventID": "e49972cb-b394-43e2-aab5-602f1fb56f85",
	      "eventName": "SendSerialConsoleSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-11-26T15:35:23Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "844015365555",
	      "requestID": "d392c0ca-351f-472f-9ca3-b411beb9df9c",
	      "requestParameters": {
	         "instanceId": "i-B2ABDCa5b78E0f1dd",
	         "monitorMode": false,
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu",
	         "serialPort": 0
	      },
	      "responseElements": {
	         "requestId": "d392c0ca-351f-472f-9ca3-b411beb9df9c",
	         "success": true
	      },
	      "sourceIPAddress": "201.252.42.03",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.cniso-east-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_b0fedc91-bd4a-4ba1-a776-80e707fef2a0",
	      "userIdentity": {
	         "accessKeyId": "ASIA2HJRQF0DHNYEE9N1",
	         "accountId": "844015365555",
	         "arn": "arn:aws:sts::844015365555:assumed-role/AWSReservedSSOrandoml3I7nL6f7BmB@gmail.com",
	         "principalId": "AROAEMHZD694LU95MUYOP:randomca0L529zwNAY@gmail.com",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-11-26T15:14:58Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "844015365555",
	               "arn": "arn:aws:iam::844015365555:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_account-admin_599c9e90e350d2ff",
	               "principalId": "AROAEMHZD694LU95MUYOP",
	               "type": "Role",
	               "userName": "AWSReservedSSO_account-admin_599c9e90e350d2ff"
	            },
	            "webIdFederationData": {}
	         },
	         "type": "AssumedRole"
	      }
	   },
	   {
	      "awsRegion": "cniso-east-3r",
	      "eventCategory": "Management",
	      "eventID": "f4dc86c9-6b22-4643-a0e8-fcb97fcfae68",
	      "eventName": "SendSerialConsoleSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-11-26T15:35:22Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "844015365555",
	      "requestID": "88c8e41e-7754-4377-983f-140f8ca5617e",
	      "requestParameters": {
	         "instanceId": "i-D46eD8FCdefED5aAE",
	         "monitorMode": false,
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu",
	         "serialPort": 0
	      },
	      "responseElements": {
	         "requestId": "88c8e41e-7754-4377-983f-140f8ca5617e",
	         "success": true
	      },
	      "sourceIPAddress": "201.252.42.03",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.cniso-east-3r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_b0fedc91-bd4a-4ba1-a776-80e707fef2a0",
	      "userIdentity": {
	         "accessKeyId": "ASIA2HJRQF0DHNYEE9N1",
	         "accountId": "844015365555",
	         "arn": "arn:aws:sts::844015365555:assumed-role/AWSReservedSSOrandoml3I7nL6f7BmB@gmail.com",
	         "principalId": "AROAEMHZD694LU95MUYOP:randomca0L529zwNAY@gmail.com",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-11-26T15:14:58Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "844015365555",
	               "arn": "arn:aws:iam::844015365555:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_account-admin_599c9e90e350d2ff",
	               "principalId": "AROAEMHZD694LU95MUYOP",
	               "type": "Role",
	               "userName": "AWSReservedSSO_account-admin_599c9e90e350d2ff"
	            },
	            "webIdFederationData": {}
	         },
	         "type": "AssumedRole"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
