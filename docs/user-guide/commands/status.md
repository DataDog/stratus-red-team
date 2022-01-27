---
title: status
---
# `stratus status`

Displays the current state of the attack techniques.

See: [Stratus Red Team attack technique states](../../getting-started/#state-machine)

## Sample Usage

```bash title="List the current state of available attack techniques"
stratus status
```

### Sample output

```
+------------------------------------------------------------+--------------------------------------------------------+-------------+
| ID                                                         | NAME                                                   | STATUS      |
+------------------------------------------------------------+--------------------------------------------------------+-------------+
| aws.defense-evasion.cloudtrail-stop                        | Stop a CloudTrail Trail                                | WARM        |
| aws.defense-evasion.organizations-leave                    | Attempt to Leave the AWS Organization                  | COLD        |
| aws.defense-evasion.vpc-remove-flow-logs                   | Remove VPC Flow Logs                                   | WARM        |
| aws.persistence.iam-backdoor-user                          | Create an Access Key on an IAM User                    | DETONATED   |
+------------------------------------------------------------+--------------------------------------------------------+-------------+
```