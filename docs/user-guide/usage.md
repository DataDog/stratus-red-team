# Usage


List available TTPs using:

```bash
# List all techniques
stratus list

# List all persistence techniques
stratus list --mitre-attack-tactic persistence

# List all AWS tactics
stratus list --platform aws
```

View the detail of a specific technique:

```bash
$ stratus show aws.exfiltration.ec2-share-ebs-snapshot
Exfiltrates an EBS snapshot by sharing it with an external AWS account.

Warm-up: Creates an EBS volume and a snapshot.
Detonation: Calls ModifySnapshotAttribute to share the snapshot.
```

Detonate an attack technique using:

```bash
stratus detonate aws.exfiltration.ec2-share-ebs-snapshot
```

This will handle warm-up and detonation (but not clean-up - explicitly use `--clean-up` for this).

Alternatively, you can handle warm-up and detonation independently:

```bash
stratus warmup aws.exfiltration.ec2-share-ebs-snapshot
stratus detonate aws.exfiltration.ec2-share-ebs-snapshot
```

Cleanup can be done through:

```bash
stratus cleanup aws.exfiltration.ec2-share-ebs-snapshot
```

At any time, you can view the state of the TTPs:

```bash
stratus status

+------------------------------------------------------------+-----------+
| TECHNIQUE                                                  | STATUS    |
+------------------------------------------------------------+-----------+
| aws.exfiltration.ec2-share-ebs-snapshot | WARM      |
| aws.persistence.iam-backdoor-user                          | DETONATED |
| aws.persistence.iam-backdoor-role                          | WARM      |
| aws.persistence.iam-create-admin-user                         | COLD      |
+------------------------------------------------------------+-----------+
```