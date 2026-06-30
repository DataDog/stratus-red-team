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

### JSON output

```bash title="Output technique states as JSON"
stratus status --output json
```

```json
[
  {
    "id": "aws.defense-evasion.cloudtrail-stop",
    "name": "Stop a CloudTrail Trail",
    "state": "WARM"
  },
  {
    "id": "aws.persistence.iam-backdoor-user",
    "name": "Create an Access Key on an IAM User",
    "state": "DETONATED"
  }
]
```