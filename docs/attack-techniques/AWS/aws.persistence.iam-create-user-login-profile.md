---
title: Create a Login Profile on an IAM User
---

# Create a Login Profile on an IAM User




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence
- Privilege Escalation

## Description


Establishes persistence by creating a Login Profile on an existing IAM user. This allows an attacker to access an IAM
user intended to be used programmatically through the AWS console usual login process. 

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an IAM user

<span style="font-variant: small-caps;">Detonation</span>: 

- Create an IAM Login Profile on the user

References:

- https://permiso.io/blog/s/approach-to-detection-androxgh0st-greenbot-persistence/
- https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/
- https://blog.darklab.hk/2021/07/06/trouble-in-paradise/
- https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-create-user-login-profile
```
## Detection


Through CloudTrail's <code>CreateLoginProfile</code> or <code>UpdateLoginProfile</code> events.

In particular, it's suspicious when these events occur on IAM users intended to be used programmatically.


