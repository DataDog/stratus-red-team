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


??? "View raw detonation logs"

    ```json hl_lines="6 58 110"

    [
	   {
	      "awsRegion": "me-northnorth-1r",
	      "eventCategory": "Management",
	      "eventID": "361b1533-7e1f-4e45-a34f-3e7958253c08",
	      "eventName": "SendSerialConsoleSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-11-26T10:51:12Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "673637476045",
	      "requestID": "e96ac1bf-51f0-4560-be1f-bb94bf4dc177",
	      "requestParameters": {
	         "instanceId": "i-7C5CBC1114349DB57",
	         "monitorMode": false,
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu",
	         "serialPort": 0
	      },
	      "responseElements": {
	         "requestId": "e96ac1bf-51f0-4560-be1f-bb94bf4dc177",
	         "success": true
	      },
	      "sourceIPAddress": "218.215.244.17",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.me-northnorth-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_f0e522d8-53af-4063-aa42-e5601970f482",
	      "userIdentity": {
	         "accessKeyId": "ASIA7J3OZH03T5QLALG3",
	         "accountId": "673637476045",
	         "arn": "arn:aws:sts::673637476045:assumed-role/AWSReservedSSOrandomkOMjLGj7NVc3@gmail.com",
	         "principalId": "AROARI36U4FA2S9L0G6R4:randomjci5H04kojgi@gmail.com",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-11-26T10:42:10Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "673637476045",
	               "arn": "arn:aws:iam::673637476045:role/sample-role",
	               "principalId": "AROARI36U4FA2S9L0G6R4",
	               "type": "Role",
	               "userName": "sample-role"
	            },
	            "webIdFederationData": {}
	         },
	         "type": "AssumedRole"
	      }
	   },
	   {
	      "awsRegion": "me-northnorth-1r",
	      "eventCategory": "Management",
	      "eventID": "3c56f906-ae4c-428b-8840-87f96ad2fb53",
	      "eventName": "SendSerialConsoleSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-11-26T10:51:12Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "673637476045",
	      "requestID": "034be9c3-8ce9-4bc4-b174-96270e9cb784",
	      "requestParameters": {
	         "instanceId": "i-1150EdC0D493fbb5c",
	         "monitorMode": false,
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu",
	         "serialPort": 0
	      },
	      "responseElements": {
	         "requestId": "034be9c3-8ce9-4bc4-b174-96270e9cb784",
	         "success": true
	      },
	      "sourceIPAddress": "218.215.244.17",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.me-northnorth-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_f0e522d8-53af-4063-aa42-e5601970f482",
	      "userIdentity": {
	         "accessKeyId": "ASIA7J3OZH03T5QLALG3",
	         "accountId": "673637476045",
	         "arn": "arn:aws:sts::673637476045:assumed-role/AWSReservedSSOrandomkOMjLGj7NVc3@gmail.com",
	         "principalId": "AROARI36U4FA2S9L0G6R4:randomjci5H04kojgi@gmail.com",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-11-26T10:42:10Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "673637476045",
	               "arn": "arn:aws:iam::673637476045:role/sample-role",
	               "principalId": "AROARI36U4FA2S9L0G6R4",
	               "type": "Role",
	               "userName": "sample-role"
	            },
	            "webIdFederationData": {}
	         },
	         "type": "AssumedRole"
	      }
	   },
	   {
	      "awsRegion": "me-northnorth-1r",
	      "eventCategory": "Management",
	      "eventID": "40bff50c-9205-406c-b47e-b928e668cbb9",
	      "eventName": "SendSerialConsoleSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-11-26T10:51:12Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "673637476045",
	      "requestID": "b441ad3b-66d5-4497-a364-ed7b047a2ebe",
	      "requestParameters": {
	         "instanceId": "i-DEbfB3Feb0e927a6c",
	         "monitorMode": false,
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu",
	         "serialPort": 0
	      },
	      "responseElements": {
	         "requestId": "b441ad3b-66d5-4497-a364-ed7b047a2ebe",
	         "success": true
	      },
	      "sourceIPAddress": "218.215.244.17",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.me-northnorth-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_f0e522d8-53af-4063-aa42-e5601970f482",
	      "userIdentity": {
	         "accessKeyId": "ASIA7J3OZH03T5QLALG3",
	         "accountId": "673637476045",
	         "arn": "arn:aws:sts::673637476045:assumed-role/AWSReservedSSOrandomkOMjLGj7NVc3@gmail.com",
	         "principalId": "AROARI36U4FA2S9L0G6R4:randomjci5H04kojgi@gmail.com",
	         "sessionContext": {
	            "attributes": {
	               "creationDate": "2024-11-26T10:42:10Z",
	               "mfaAuthenticated": "false"
	            },
	            "sessionIssuer": {
	               "accountId": "673637476045",
	               "arn": "arn:aws:iam::673637476045:role/sample-role",
	               "principalId": "AROARI36U4FA2S9L0G6R4",
	               "type": "Role",
	               "userName": "sample-role"
	            },
	            "webIdFederationData": {}
	         },
	         "type": "AssumedRole"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
