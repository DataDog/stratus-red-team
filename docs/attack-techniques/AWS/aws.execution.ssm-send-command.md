---
title: Usage of ssm:SendCommand on multiple instances
---

# Usage of ssm:SendCommand on multiple instances

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Execution

## Description


Simulates an attacker utilizing AWS Systems Manager (SSM) to execute commands through SendCommand on multiple EC2 instances.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create multiple EC2 instances and a VPC (takes a few minutes).

<span style="font-variant: small-caps;">Detonation</span>: 

- Runs <code>ssm:SendCommand</code> on several EC2 instances, to execute the command <code>echo "id=$(id), hostname=$(hostname)"</code> on each of them.

References:

- https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/#send-command
- https://www.chrisfarris.com/post/aws-ir/
- https://www.invictus-ir.com/news/aws-cloudtrail-cheat-sheet
- https://securitycafe.ro/2023/01/17/aws-post-explitation-with-ssm-sendcommand/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.execution.ssm-send-command
```
## Detection


Identify, through CloudTrail's <code>SendCommand</code> event, especially when <code>requestParameters.instanceIds</code> contains several instances. Sample event:

```json
{
  "eventSource": "ssm.amazonaws.com",
  "eventName": "SendCommand",
  "requestParameters": {
    "instanceIds": [
      "i-0f364762ca43f9661",
      "i-0a86d1f61db2b9b5d",
      "i-08a69bfbe21c67e70"
    ],
    "documentName": "AWS-RunShellScript",
    "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS",
    "interactive": false
  }
}
```

While this technique uses a single call to <code>ssm:SendCommand</code> on several instances, an attacker may use one call per instance to execute commands on. In that case, the <code>SendCommand</code> event will be emitted for each call.


