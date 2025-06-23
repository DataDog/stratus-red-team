---
title: Console Login without MFA
---

# Console Login without MFA


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Initial Access


- Threat Technique Catalog for AWS:
  
    - [Valid Accounts: IAM Users](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1078.A001.html) (T1078.A001)
  


## Description


Simulates a login to the AWS Console for an IAM user without multi-factor authentication (MFA).

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM user
- Create a console profile for this user so it can log in to the AWS Console

<span style="font-variant: small-caps;">Detonation</span>:

- Log in to the AWS Console

References:

- https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/
- https://naikordian.github.io/blog/posts/brute-force-aws-console/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.initial-access.console-login-without-mfa
```
## Detection


Using CloudTrail <code>ConsoleLogin</code> event. The field <code>additionalEventData.MFAUser</code> is set to
<code>No</code> when the authentication does not use MFA.

Sample CloudTrail event (redacted for clarity):

```json hl_lines="4 14 19 24"
{
	"userIdentity": {
		"session_name": "console-user-wgrosmao",
		"type": "IAMUser",
		"arn": "arn:aws:iam::123456789123:user/console-user-wgrosmao",
		"accountId": "123456789123",
		"userName": "console-user-wgrosmao",
		"principalId": "AIDA254BBSGPKOYEB6PTV"
	},
	"eventSource": "signin.amazonaws.com",
	"eventType": "AwsConsoleSignIn",
	"eventCategory": "Management",
	"awsRegion": "us-east-1",
	"eventName": "ConsoleLogin",
	"readOnly": false,
	"eventTime": "2022-05-30T14:24:34Z",
	"managementEvent": true,
	"additionalEventData": {
		"MFAUsed": "No",
		"LoginTo": "https://console.aws.amazon.com/console/home",
		"MobileVersion": "No"
	},
	"responseElements": {
		"ConsoleLogin": "Success"
	}
}
```

Note that for failed console authentication events, the field <code>userIdentity.arn</code> is not set (see https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html#cloudtrail-aws-console-sign-in-events-iam-user-failure).



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `signin:ConsoleLogin`


??? "View raw detonation logs"

    ```json hl_lines="11"

    [
	   {
	      "additionalEventData": {
	         "LoginTo": "https://console.aws.amazon.com/console/home",
	         "MFAUsed": "No",
	         "MobileVersion": "No"
	      },
	      "awsRegion": "eu-west-2r",
	      "eventCategory": "Management",
	      "eventID": "865d9377-9c6b-4fd7-8aad-725e95f6a140",
	      "eventName": "ConsoleLogin",
	      "eventSource": "signin.amazonaws.com",
	      "eventTime": "2024-08-02T08:53:24Z",
	      "eventType": "AwsConsoleSignIn",
	      "eventVersion": "1.08",
	      "managementEvent": true,
	      "readOnly": false,
	      "recipientAccountId": "562283505220",
	      "requestParameters": null,
	      "responseElements": {
	         "ConsoleLogin": "Success"
	      },
	      "sourceIPAddress": "225.01.00.16",
	      "tlsDetails": {
	         "cipherSuite": "TLS_AES_128_GCM_SHA256",
	         "clientProvidedHostHeader": "signin.aws.amazon.com",
	         "tlsVersion": "TLSv1.3"
	      },
	      "userAgent": "stratus-red-team_fccf7123-0651-41f5-b06c-460da5ee1c94",
	      "userIdentity": {
	         "accountId": "562283505220",
	         "arn": "arn:aws:iam::562283505220:user/stratus-red-team-nmfalu-jfzdtsvchl",
	         "principalId": "AIDA1ERT0661IN5R239V",
	         "type": "IAMUser",
	         "userName": "stratus-red-team-nmfalu-jfzdtsvchl"
	      }
	   }
	]
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
