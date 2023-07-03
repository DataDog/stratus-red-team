---
title: Console Login without MFA
---

# Console Login without MFA


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Initial Access

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


