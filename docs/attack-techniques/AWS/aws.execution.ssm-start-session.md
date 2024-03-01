---
title: Usage of ssm:StartSession on multiple instances
---

# Usage of ssm:StartSession on multiple instances

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Execution

## Description


Simulates an attacker utilizing AWS Systems Manager (SSM) StartSession to gain unauthorized interactive access to multiple EC2 instances.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create multiple EC2 instances and a VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>: 

- Initiates a connection to the EC2 for a Session Manager session.

References:

- https://awstip.com/responding-to-an-attack-in-aws-9048a1a551ac (evidence of usage in the wild)
- https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/#session-manager
- https://unit42.paloaltonetworks.com/cloud-lateral-movement-techniques/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.execution.ssm-start-session
```
## Detection


Identify, through CloudTrail's <code>StartSession</code> event, when a user is starting an interactive session to multiple EC2 instances. Sample event:

```
{
  "eventSource": "ssm.amazonaws.com",
  "eventName": "StartSession",
  "requestParameters": {
    "target": "i-123456"
  },
  "responseElements": {
        "sessionId": "...",
        "tokenValue": "Value hidden due to security reasons.",
        "streamUrl": "wss://ssmmessages.eu-west-1.amazonaws.com/v1/data-channel/..."
   },
}
```


