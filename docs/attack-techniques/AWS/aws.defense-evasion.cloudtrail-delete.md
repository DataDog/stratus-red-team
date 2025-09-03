---
title: Delete CloudTrail Trail
---

# Delete CloudTrail Trail




Platform: AWS

## Mappings

- MITRE ATT&CK
    - Defense Evasion


- Threat Technique Catalog for AWS:
  
    - [Impair Defenses: Disable Cloud Logs](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1562.008.html) (T1562.008)
  


## Description


Delete a CloudTrail trail. Simulates an attacker disrupting CloudTrail logging.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a CloudTrail trail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Delete the CloudTrail trail.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.cloudtrail-delete
```
## Detection


Identify when a CloudTrail trail is deleted, through CloudTrail's <code>DeleteTrail</code> event.

GuardDuty also provides a dedicated finding type, [Stealth:IAMUser/CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled).



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `cloudtrail:DeleteTrail`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "megov-westwest-1r",
	      "eventCategory": "Management",
	      "eventID": "ee73c230-44bc-4492-8542-cfb189eae287",
	      "eventName": "DeleteTrail",
	      "eventSource": "cloudtrail.amazonaws.com",
	      "eventTime": "2024-07-31T12:46:41Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.10",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "847129010505",
	      "requestID": "206c2187-a29f-45bf-86a2-a87d99ff7186",
	      "requestParameters": {
	         "name": "stratus-red-team-cloudtraild-trail-kvrwohmiai"
	      },
	      "responseElements": null,
	      "sourceIPAddress": "08.1.250.216",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "cloudtrail.megov-westwest-1r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_a007fa03-86e2-4130-be03-ee7b7b10edcc",
	      "userIdentity": {
	         "accessKeyId": "AKIAFBJ48BV9CGRBRKGM",
	         "accountId": "847129010505",
	         "arn": "arn:aws:iam::847129010505:user/christophe",
	         "principalId": "AIDALE4EP1EPEPX3SDR8",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
