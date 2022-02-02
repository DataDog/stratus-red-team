---
title: Exfiltrate EBS Snapshot by Sharing It
---

# Exfiltrate EBS Snapshot by Sharing It


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

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
stratus detonate aws.exfiltration.ec2-share-ebs-snapshot
```
## Detection


Through CloudTrail's <code>ModifySnapshotAttribute</code> event, when <code>requestParameters.createVolumePermission</code> shows
that the EBS snapshot was shared with a new or unknown AWS account, such as:

<pre><code>"requestParameters": {
  "snapshotId": "snap-01b3f7d87a02559a1",
  "attributeType": "CREATE_VOLUME_PERMISSION",
  "createVolumePermission": {
    "add": {
	  "items": [{ "userId": "111111111111" }]
    }
  }
}</code></pre>

An attacker can also make an EBS snapshot completely public. In this case, the <code>item</code> entry 
will look like <code>{"groups":"all"}</code>. 


