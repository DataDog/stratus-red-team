---
title: Exfiltrate RDS Snapshot by Sharing
---

# Exfiltrate RDS Snapshot by Sharing

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Shares a RDS Snapshot with an external AWS account to simulate an attacker exfiltrating a database.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a RDS Instance (slow, around 10 minutes)
- Create a RDS Snapshot

<span style="font-variant: small-caps;">Detonation</span>:

- Call rds:ModifyDBSnapshotAttribute to share the snapshot with an external AWS account


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.rds-share-snapshot
```
## Detection


Through CloudTrail's <code>ModifyDBSnapshotAttribute</code> event, when both:

- <code>requestParameters.attributeName</code> is <code>restore</code>
- and, <code>requestParameters.launchPermission</code> shows that the RDS snapshot was shared with a new or unknown AWS account, such as:

<pre><code>"requestParameters": {
  "dBSnapshotIdentifier": "my-db-snapshot",
  "attributeName": "restore"
  "valuesToAdd": ["193672423079"],
}</code></pre>

An attacker can also make an RDS snapshot completely public. In this case, the value of <code>valuesToAdd</code> is <code>["all"]</code>. 





## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `rds:ModifyDBSnapshotAttribute`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "meiso-eastwest-2r",
	      "eventCategory": "Management",
	      "eventID": "fef2bf02-bbea-4d0f-a91c-e6ccfe3fba46",
	      "eventName": "ModifyDBSnapshotAttribute",
	      "eventSource": "rds.amazonaws.com",
	      "eventTime": "2024-08-01T12:38:06Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "171471557522",
	      "requestID": "3fd13676-52a0-4680-8491-71a8e28ea7f5",
	      "requestParameters": {
	         "attributeName": "restore",
	         "dBSnapshotIdentifier": "exfiltration",
	         "valuesToAdd": [
	            "503161813013"
	         ]
	      },
	      "responseElements": {
	         "dBSnapshotAttributes": [
	            {
	               "attributeName": "restore",
	               "attributeValues": [
	                  "503161813013"
	               ]
	            }
	         ],
	         "dBSnapshotIdentifier": "exfiltration"
	      },
	      "sourceIPAddress": "204.10.215.184",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "rds.meiso-eastwest-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_5ca5319a-2127-4f13-a878-495bc59244b3",
	      "userIdentity": {
	         "accessKeyId": "AKIAIYTVC64GTXUFCS2X",
	         "accountId": "171471557522",
	         "arn": "arn:aws:iam::171471557522:user/christophe",
	         "principalId": "AIDA3MGXB5NR71XRJU40",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
