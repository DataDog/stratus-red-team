---
title: Share an EBS Volume for Cross-Account Cloning
---

# Share an EBS Volume for Cross-Account Cloning


 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Exfiltration


- Threat Technique Catalog for AWS:
  
    - [Modify Cloud Compute Infrastructure](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1578.html) (T1578)
  


## Description


Exfiltrates an EBS volume by sharing it with an external AWS account through AWS Resource Access Manager (RAM).

Using the <a href="https://aws.amazon.com/blogs/aws/introducing-amazon-ebs-volume-clones-across-aws-accounts/">EBS Volume Clones across AWS accounts</a> feature, sharing a volume
with the <code>AWSRAMPermissionEBSVolumeCopyAccess</code> managed permission allows the recipient
account to create a cross-account clone of the volume and exfiltrate its data.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create an EBS volume
- Create a RAM resource share with the <code>AWSRAMPermissionEBSVolumeCopyAccess</code> managed permission

<span style="font-variant: small-caps;">Detonation</span>:

- Call ram:AssociateResourceShare to share the EBS volume with an external, fictitious AWS account


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.exfiltration.ec2-share-ebs-volume
```
## Detection


Through CloudTrail's <code>AssociateResourceShare</code> event (event source <code>ram.amazonaws.com</code>), when
<code>requestParameters</code> shows an EBS volume being shared with a new or unknown AWS account, such as:

<pre><code>"requestParameters": {
  "principals": ["999999999999"],
  "resourceArns": ["arn:aws:ec2:us-east-1:111111111111:volume/vol-0c741433d3ddb73c7"],
  "resourceShareArn": "arn:aws:ram:us-east-1:111111111111:resource-share/24048254-7629-41e0-ba73-f129af0cc68d"
}</code></pre>

In the same event <code>responseElements.resourceShareAssociations</code> carries an
<code>external</code> flag indicating whether RAM treats the recipient principal as outside the owner's AWS Organizations
boundary (see <a href="https://docs.aws.amazon.com/ram/latest/APIReference/API_ResourceShareAssociation.html">RAM API reference</a>).
<code>"external": true</code>. 

Note: RAM only recognizes a principal as in-organization when sharing with AWS Organizations is enabled (<code>ram:EnableSharingWithAwsOrganization</code>); when it is disabled,
an account in the same organization is reported as <code>external</code>.

<pre><code>"responseElements": {
  "resourceShareAssociations": [
    {
      "associationType": "RESOURCE",
      "associatedEntity": "arn:aws:ec2:us-east-1:111111111111:volume/vol-0c741433d3ddb73c7",
      "external": false
    },
    {
      "associationType": "PRINCIPAL",
      "associatedEntity": "999999999999",
      "external": true
    }
  ]
}</code></pre>

When the recipient account clones the shared volume, the <code>CopyVolumes</code> event is logged in
<b>both</b> the recipient account and the volume owner's account (see [AWS docs](https://docs.aws.amazon.com/ebs/latest/userguide/share-volume.html)).

In the owner's account, <code>userIdentity.accountId</code> contains the attacker's account ID, <code>recipientAccountId</code> contains the
victim's account ID where the volume was originally created, and <code>CopyVolumesRequest.SourceVolumeId</code> identifies the volume:

<pre><code>{
  "userIdentity": {
    "type": "AssumedRole",
    "accountId": "999999999999"
  },
  "eventSource": "ec2.amazonaws.com",
  "eventName": "CopyVolumes",
  "awsRegion": "us-east-1",
  "requestParameters": {
    "CopyVolumesRequest": {
      "SourceVolumeId": "vol-0c741433d3ddb73c7"
    }
  },
  "readOnly": false,
  "managementEvent": true,
  "recipientAccountId": "111111111111"
}</code></pre>

Note that detonating this attack technique with Stratus Red Team does *not* simulate an attacker cloning the volume from their account (only sharing it from your account).


