---
title: Exfiltrate RDS Snapshot by Sharing
---

# Exfiltrate RDS Snapshot by Sharing

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## MITRE ATT&CK Tactics


- Exfiltration

## Description


Shares a RDS Snapshot with an external AWS account to simulate an attacker exfiltrating a database.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a RDS Instance (slow, around 10 minutes)
- Create a RDS Snapshot

<span style="font-variant: small-caps;">Detonation</span>:

- Call rds:ModifyDBSnapshotAttribute to share the snapshot with an external AWS account


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.rds-share-snapshot
```