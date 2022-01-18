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
$ stratus show aws.exfiltration.ebs-snapshot-shared-with-external-account
Exfiltrates an EBS snapshot by sharing it with an external AWS account.

Warm-up: Creates an EBS volume and a snapshot.
Detonation: Calls ModifySnapshotAttribute to share the snapshot.
```

Detonate an attack technique using:

```bash
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account
```

This will handle warm-up and detonation (but not clean-up - explicitly use `--clean-up` for this).

Alternatively, you can handle warm-up and detonation independently:

```bash
stratus warmup aws.exfiltration.ebs-snapshot-shared-with-external-account
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account
```

Cleanup can be done through:

```bash
stratus cleanup aws.exfiltration.ebs-snapshot-shared-with-external-account
```

At any time, you can view the state of the TTPs:

```bash
stratus status

+------------------------------------------------------------+-----------+
| TECHNIQUE                                                  | STATUS    |
+------------------------------------------------------------+-----------+
| aws.exfiltration.ebs-snapshot-shared-with-external-account | WARM      |
| aws.persistence.backdoor-iam-user                          | DETONATED |
| aws.persistence.backdoor-iam-role                          | WARM      |
| aws.persistence.malicious-iam-user                         | COLD      |
+------------------------------------------------------------+-----------+
```