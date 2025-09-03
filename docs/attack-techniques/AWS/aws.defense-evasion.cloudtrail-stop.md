---
title: Stop CloudTrail Trail
---

# Stop CloudTrail Trail


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Defense Evasion


- Threat Technique Catalog for AWS:
  
    - [Impair Defenses: Disable Cloud Logs](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1562.008.html) (T1562.008)
  


## Description


Stops a CloudTrail Trail from logging. Simulates an attacker disrupting CloudTrail logging.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create a CloudTrail Trail.

<span style="font-variant: small-caps;">Detonation</span>: 

- Call cloudtrail:StopLogging to stop CloudTrail logging.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.defense-evasion.cloudtrail-stop
```
## Detection


Identify when a CloudTrail trail is disabled, through CloudTrail's <code>StopLogging</code> event.

GuardDuty also provides a dedicated finding type, [Stealth:IAMUser/CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled).



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `cloudtrail:StopLogging`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "apiso-centralnorth-2r",
	      "eventCategory": "Management",
	      "eventID": "10163ed2-2253-469d-a5ee-cbc6651f8934",
	      "eventName": "StopLogging",
	      "eventSource": "cloudtrail.amazonaws.com",
	      "eventTime": "2024-07-31T13:06:24Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.10",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "143434273843",
	      "requestID": "14c891b6-11b5-4787-ae97-64a974977078",
	      "requestParameters": {
	         "name": "stratus-red-team-ct-stop-trail-buykxbqejv"
	      },
	      "responseElements": null,
	      "sourceIPAddress": "86.245.153.234",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "cloudtrail.apiso-centralnorth-2r.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_c97089f1-1ae3-4ecc-b006-f5e8fd0f2571",
	      "userIdentity": {
	         "accessKeyId": "AKIAGGWFBBHBE7D3M9WI",
	         "accountId": "143434273843",
	         "arn": "arn:aws:iam::143434273843:user/christophe",
	         "principalId": "AIDAOC1SYDVN0AF0FMMR",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
