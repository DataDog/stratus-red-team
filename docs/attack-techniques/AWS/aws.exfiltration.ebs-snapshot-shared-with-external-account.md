# Exfiltrate EBS Snapshot through snapshot sharing

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates an EBS snapshot by sharing it with an external AWS account.

Warm-up: Creates an EBS volume and a snapshot.

Detonation: Calls ModifySnapshotAttribute to share the snapshot.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account
```