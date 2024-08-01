---
title: Disable CloudTrail Logging Through Event Selectors
---

# Disable CloudTrail Logging Through Event Selectors


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Defense Evasion

## Description


Disrupt CloudTrail Logging by creating an event selector on the Trail, filtering out all management events.

Reference: https://github.com/RhinoSecurityLabs/Cloud-Security-Research/tree/master/AWS/cloudtrail_guardduty_bypass

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a CloudTrail trail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create a CloudTrail event selector to disable management events, through cloudtrail:PutEventSelectors


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.cloudtrail-event-selectors
```
## Detection


Identify when event selectors of a CloudTrail trail are updated, through CloudTrail's <code>PutEventSelectors</code> event.





## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `cloudtrail:PutEventSelectors`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "cn-northsouth-2r",
	      "eventCategory": "Management",
	      "eventID": "c2a89408-340a-42f0-8ace-75d9f5769393",
	      "eventName": "PutEventSelectors",
	      "eventSource": "cloudtrail.amazonaws.com",
	      "eventTime": "2024-07-31T12:50:02Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.10",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "958312252124",
	      "requestID": "5176273c-0497-47e9-8f4c-840b62e7fc9a",
	      "requestParameters": {
	         "eventSelectors": [
	            {
	               "dataResources": [
	                  {
	                     "type": "AWS::S3::Object",
	                     "values": []
	                  },
	                  {
	                     "type": "AWS::Lambda::Function",
	                     "values": []
	                  }
	               ],
	               "excludeManagementEventSources": [],
	               "includeManagementEvents": false,
	               "readWriteType": "ReadOnly"
	            }
	         ],
	         "trailName": "stratus-red-team-ctes-trail-khlvciwdor"
	      },
	      "responseElements": {
	         "eventSelectors": [
	            {
	               "dataResources": [
	                  {
	                     "type": "AWS::S3::Object",
	                     "values": []
	                  },
	                  {
	                     "type": "AWS::Lambda::Function",
	                     "values": []
	                  }
	               ],
	               "excludeManagementEventSources": [],
	               "includeManagementEvents": false,
	               "readWriteType": "ReadOnly"
	            }
	         ],
	         "trailARN": "arn:aws:cloudtrail:cn-northsouth-2r:958312252124:trail/stratus-red-team-ctes-trail-khlvciwdor"
	      },
	      "sourceIPAddress": "221.254.191.250",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "cloudtrail.cn-northsouth-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_ce507fbd-078a-4e4c-975d-d80cb80df469",
	      "userIdentity": {
	         "accessKeyId": "AKIA2I0BSXU5LNRWIN0K",
	         "accountId": "958312252124",
	         "arn": "arn:aws:iam::958312252124:user/christophe",
	         "principalId": "AIDA3JXGLTFY4HTLVVO7",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
