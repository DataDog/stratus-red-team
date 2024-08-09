---
title: Remove VPC Flow Logs
---

# Remove VPC Flow Logs




Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Removes a VPC Flog Logs configuration from a VPC.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a VPC with a VPC Flow Logs configuration.

<span style="font-variant: small-caps;">Detonation</span>: 

- Remove the VPC Flow Logs configuration.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.vpc-remove-flow-logs
```
## Detection


Using CloudTrail's <code>DeleteFlowLogs</code> event.

To reduce the risk of false positives related to VPC deletion in development environments, alerts can be raised
only when <code>DeleteFlowLogs</code> is not closely followed by <code>DeleteVpc</code>.



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `ec2:DeleteFlowLogs`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "megov-south-1r",
	      "eventCategory": "Management",
	      "eventID": "ded2f5af-f3a5-46d2-a170-a23206a32c36",
	      "eventName": "DeleteFlowLogs",
	      "eventSource": "ec2.amazonaws.com",
	      "eventTime": "2024-07-31T15:07:49Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "498376118699",
	      "requestID": "96d51d7f-c18d-45b9-8315-9aa0fde21e88",
	      "requestParameters": {
	         "DeleteFlowLogsRequest": {
	            "FlowLogId": {
	               "content": "fl-0e17aa62a21d4bbfe",
	               "tag": 1
	            }
	         }
	      },
	      "responseElements": {
	         "DeleteFlowLogsResponse": {
	            "requestId": "96d51d7f-c18d-45b9-8315-9aa0fde21e88",
	            "unsuccessful": "",
	            "xmlns": "http://ec2.amazonaws.com/doc/2016-11-15/"
	         }
	      },
	      "sourceIPAddress": "206.90.1.223",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "ec2.megov-south-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_5d25952b-37cb-46cc-a135-3407cbbca7bf",
	      "userIdentity": {
	         "accessKeyId": "AKIA5Q8Z0GHOBYSEN9D6",
	         "accountId": "498376118699",
	         "arn": "arn:aws:iam::498376118699:user/christophe",
	         "principalId": "AIDACKW2I5F25HSI3O4J",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
