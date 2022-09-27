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

When an attacker copies the snapshot to their own AWS account or creates an EBS volume for it, the <code>SharedSnapshotCopyInitiated</code> (respectively <code>SharedSnapshotVolumeCreated</code>) event is logged (see [AWS docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html#shared-snapshot-cloudtrail-logging)). 
In that case, <code>userIdentity.accountId</code> contains the attacker's account ID and <code>recipientAccountId</code> contains the victim's account ID where the snapshot was originally created.

<pre><code>{
  "userIdentity": {
    "invokedBy": "ec2.amazonaws.com",
    "type": "AWSAccount",
    "accountId": "999999999999"
  },
  "eventSource": "ec2.amazonaws.com",
  "eventVersion": "1.08",
  "eventTime": "2022-09-27T07:58:49Z",
  "service": "cloudtrail",
  "eventName": "SharedSnapshotCopyInitiated",
  "eventType": "AwsServiceEvent",
  "eventCategory": "Management",
  "awsRegion": "us-east-1",
    "serviceEventDetails": {
    "snapshotId": "snap-12345"
  },
  "readOnly": false,
  "managementEvent": true,
  "recipientAccountId": "111111111111"
 }
 </code></pre>
 
 Note that detonating this attack technique with Stratus Red Team does *not* simulate an attacker accessing the snapshot from their account (only sharing it publicly from your account).


