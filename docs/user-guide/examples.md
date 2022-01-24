# Examples

This page contains a full example of using Stratus Red Team.

## Example 1: Basic usage

## Authenticating to AWS

First, we'll authenticate to AWS using [aws-vault](https://github.com/99designs/aws-vault):

```bash
$ aws-vault exec sandbox-account
# If using an IAM user, use instead: aws-vault exec sandbox-account --no-session

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

## Example 2: Advanced usage

In this example, we want to prepare our live environment with the pre-requisites ahead of time - say, a few hours before detonating our attack techniques.

We start by warming up the techniques we're interested in:

```bash
stratus warmup aws.defense-evasion.stop-cloudtrail aws.defense-evasion.remove-vpc-flow-logs aws.persistence.backdoor-iam-user
```

We now have the pre-requisites ready:

```
CloudTrail trail arn:aws:cloudtrail:us-east-1:0123456789012:trail/my-cloudtrail-trail ready
VPC Flow Logs fl-0ef2f69f9799cf52e in VPC vpc-072ec3075f9b5046a ready
IAM user sample-legit-user ready
```

At this point, we can choose to detonate these attack techniques at any point we want. We can do it right away, or in a few hours / days:

```bash
stratus detonate aws.defense-evasion.stop-cloudtrail aws.defense-evasion.remove-vpc-flow-logs aws.persistence.backdoor-iam-user
```

```text
Stopping CloudTrail trail my-cloudtrail-trail
Removing VPC Flow Logs fl-0ef2f69f9799cf52e in VPC vpc-072ec3075f9b5046a
Creating access key on legit IAM user to simulate backdoor
```

Now, say we want to replay (i.e., detonate again) an attack technique a few times, for testing and to iterate building our threat detection rules on the side:

```
stratus detonate aws.persistence.backdoor-iam-user
```

You will notice that the second call raises an error:

```
aws.persistence.backdoor-iam-user has already been detonated and is not idempotent. 
Revert it with 'stratus revert' before detonating it again, or use --force
```

That's because the detonation of this attack technique is not idempotent, meaning it cannot be detonated multiple times without being reverted. 

Before re-detonating this technique, we need to revert it:

```
stratus revert aws.persistence.backdoor-iam-user
```

``` 
2022/01/19 15:43:35 Reverting detonation of technique aws.persistence.backdoor-iam-user
2022/01/19 15:43:35 Removing access key from IAM user sample-legit-user
2022/01/19 15:43:36 Removing access key AKIA254BBSGPJNHEDHNR
+-----------------------------------+-----------------------------------------+--------+
| ID                                | NAME                                    | STATUS |
+-----------------------------------+-----------------------------------------+--------+
| aws.persistence.backdoor-iam-user | Create an IAM Access Key on an IAM User | WARM   |
+-----------------------------------+-----------------------------------------+--------+
```

Our attack technique is now `WARM`, we can detonate it again:

```bash
stratus detonate aws.persistence.backdoor-iam-user
```

Generally, we can detonate then revert an attack technique indefinitely:

```bash
while true; do
  stratus detonate aws.persistence.backdoor-iam-user
  stratus revert aws.persistence.backdoor-iam-user
  sleep 1
done
```

Once we are done with our testing, we can clean up our techniques. Cleaning up a technique will revert its detonation logic (if applicable), then nuke all its pre-requisite resources and infrastructure:

```bash
stratus cleanup aws.defense-evasion.stop-cloudtrail aws.defense-evasion.remove-vpc-flow-logs aws.persistence.backdoor-iam-user
```