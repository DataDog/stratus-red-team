---
title: Usage of EC2 Instance Connect on multiple instances
---

# Usage of EC2 Instance Connect on multiple instances

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Lateral Movement

## Description


Simulates an attacker pushing an SSH public key to multiple EC2 instances, which then will allow anyone with the corresponding private key to 
connect directly to the systems via SSH.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create multiple EC2 instances and a VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>: 

- Adds a public SSH key to the EC2 for 60 seconds.

References:

- https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/#hands-on-keyboard-activity-begins
- https://sysdig.com/blog/2023-global-cloud-threat-report/
- https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.lateral-movement.ec2-instance-connect
```
## Detection


Identify, through CloudTrail's <code>SendSSHPublicKey</code> event, when a user is adding an SSH key to multiple EC2 instances. Sample event:

```
{
  "eventSource": "ec2-instance-connect.amazonaws.com",
  "eventName": "SendSSHPublicKey",
  "requestParameters": {
    "instanceId": "i-123456",
    "instanceOSUser": "ec2-user",
    "sSHPublicKey": "ssh-ed25519 ..."
  }
}
```





## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `ec2-instance-connect:SendSSHPublicKey`


??? "View raw detonation logs"

    ```json hl_lines="6 44 82"

    [
	   {
	      "awsRegion": "eu-south-1r",
	      "eventCategory": "Management",
	      "eventID": "0968cbec-f8df-43f3-94ba-b451aad083ed",
	      "eventName": "SendSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-08-01T13:24:47Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "572910899909",
	      "requestID": "1f1786bd-e04c-4fd9-af8c-6a5d69376c41",
	      "requestParameters": {
	         "instanceId": "i-fDb357cB7e99ad973",
	         "instanceOSUser": "ec2-user",
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu"
	      },
	      "responseElements": {
	         "requestId": "1f1786bd-e04c-4fd9-af8c-6a5d69376c41",
	         "success": true
	      },
	      "sourceIPAddress": "246.227.146.251",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.eu-south-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_84a22508-bcc6-424d-9973-3f841ebf8875",
	      "userIdentity": {
	         "accessKeyId": "AKIAGM9ZC9KUL0AYEVUM",
	         "accountId": "572910899909",
	         "arn": "arn:aws:iam::572910899909:user/christophe",
	         "principalId": "AIDAHG2QGAX7XGTRYBZ5",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "eu-south-1r",
	      "eventCategory": "Management",
	      "eventID": "1214f520-2eaf-4438-92ab-304bcf115296",
	      "eventName": "SendSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-08-01T13:24:47Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "572910899909",
	      "requestID": "b8b0d6ce-b722-4757-9649-c8a9d492a31d",
	      "requestParameters": {
	         "instanceId": "i-6D7Fb8F606130A33d",
	         "instanceOSUser": "ec2-user",
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu"
	      },
	      "responseElements": {
	         "requestId": "b8b0d6ce-b722-4757-9649-c8a9d492a31d",
	         "success": true
	      },
	      "sourceIPAddress": "246.227.146.251",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.eu-south-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_84a22508-bcc6-424d-9973-3f841ebf8875",
	      "userIdentity": {
	         "accessKeyId": "AKIAGM9ZC9KUL0AYEVUM",
	         "accountId": "572910899909",
	         "arn": "arn:aws:iam::572910899909:user/christophe",
	         "principalId": "AIDAHG2QGAX7XGTRYBZ5",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   },
	   {
	      "awsRegion": "eu-south-1r",
	      "eventCategory": "Management",
	      "eventID": "803d3bd8-44cb-4284-a4a9-cdfde3b00570",
	      "eventName": "SendSSHPublicKey",
	      "eventSource": "ec2-instance-connect.amazonaws.com",
	      "eventTime": "2024-08-01T13:24:47Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "572910899909",
	      "requestID": "98b43826-b4f9-4606-bb34-191e73734cfd",
	      "requestParameters": {
	         "instanceId": "i-9d2abfF1798C34950",
	         "instanceOSUser": "ec2-user",
	         "sSHPublicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtAlK45MAEWZ7MUY2QEmi3M6W+peGL3VCrc0qH54xRu"
	      },
	      "responseElements": {
	         "requestId": "98b43826-b4f9-4606-bb34-191e73734cfd",
	         "success": true
	      },
	      "sourceIPAddress": "246.227.146.251",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2-instance-connect.eu-south-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_84a22508-bcc6-424d-9973-3f841ebf8875",
	      "userIdentity": {
	         "accessKeyId": "AKIAGM9ZC9KUL0AYEVUM",
	         "accountId": "572910899909",
	         "arn": "arn:aws:iam::572910899909:user/christophe",
	         "principalId": "AIDAHG2QGAX7XGTRYBZ5",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
