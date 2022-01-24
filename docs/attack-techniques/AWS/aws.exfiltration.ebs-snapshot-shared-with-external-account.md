---
title: Exfiltrate EBS Snapshot by Sharing It
---

# Exfiltrate EBS Snapshot by Sharing It 

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Exfiltrates an EBS snapshot by sharing it with an external AWS account.

<span style="font-variant: small-caps;">Warm-up</span>: 

- Create an EBS volume and a snapshot.

<span style="font-variant: small-caps;">Detonation</span>: 

- Call ec2:ModifySnapshotAttribute to share the snapshot with an external, fictitious AWS account.


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.ebs-snapshot-shared-with-external-account
```