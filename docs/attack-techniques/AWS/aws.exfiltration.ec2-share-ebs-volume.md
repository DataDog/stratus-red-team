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

Note: This technique shares an unencrypted EBS volume. Accounts with EBS encryption by default enabled may encrypt new volumes with the AWS managed key, which cannot be shared (see the <a href="https://docs.aws.amazon.com/ebs/latest/userguide/share-volume.html">AWS documentation</a>).


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



## Detonation logs <span class="smallcaps w3-badge w3-light-green w3-round w3-text-sand">new!</span>

The following CloudTrail events are generated when this technique is detonated[^1]:


- `ram:AssociateResourceShare`


??? "View raw detonation logs"

    ```json hl_lines="30"

    [
	    {
	        "eventVersion": "1.11",
	        "userIdentity": {
	            "type": "AssumedRole",
	            "principalId": "AROA2YFTN25M35PXPIBO8:randomZWPRzAfS8aY2@gmail.com",
	            "arn": "arn:aws:sts::722461077209:assumed-role/AWSReservedSSO_AWSAdministratorArandomHnFPH80vz8tS@gmail.com",
	            "accountId": "986293246532",
	            "accessKeyId": "ASIAH0JI8Y2XPZBO5YY5",
	            "sessionContext": {
	                "sessionIssuer": {
	                    "type": "Role",
	                    "principalId": "AROA2YFTN25M35PXPIBO8",
	                    "arn": "arn:aws:iam::986293246532:role/aws-reserved/sso.amazonaws.com/cagov-westnorth-1r/AWSReservedSSO_AWSAdministratorAccess_a5e2839336c5dedf",
	                    "accountId": "986293246532",
	                    "userName": "AWSReservedSSO_AWSAdministratorAccess_a5e2839336c5dedf"
	                },
	                "attributes": {
	                    "creationDate": "2026-10-10T18:02:09Z",
	                    "mfaAuthenticated": "false"
	                }
	            },
	            "onBehalfOf": {
	                "userId": "92670c9793-3bb792e0-4882-4c8e-aa07-bf205e4798e3",
	                "identityStoreArn": "arn:aws:identitystore::606202301209:identitystore/d-92670c9793"
	            }
	        },
	        "eventTime": "2026-10-10T18:47:16Z",
	        "eventSource": "ram.amazonaws.com",
	        "eventName": "AssociateResourceShare",
	        "awsRegion": "cn-easteast-1r",
	        "sourceIPAddress": "208.12.253.202",
	        "userAgent": "stratus-red-team_93185f1c-9296-435a-aa81-8081b35e87f2",
	        "requestParameters": {
	            "principals": [
	                "763721234306"
	            ],
	            "resourceArns": [
	                "arn:aws:ec2:cn-easteast-1r:986293246532:volume/vol-0c741433d3ddb73c7"
	            ],
	            "resourceShareArn": "arn:aws:ram:cn-easteast-1r:986293246532:resource-share/24048254-7629-41e0-ba73-f129af0cc68d"
	        },
	        "responseElements": {
	            "resourceShareAssociations": [
	                {
	                    "associatedEntity": "arn:aws:ec2:cn-easteast-1r:986293246532:volume/vol-0c741433d3ddb73c7",
	                    "associationType": "RESOURCE",
	                    "external": false,
	                    "resourceShareArn": "arn:aws:ram:cn-easteast-1r:986293246532:resource-share/24048254-7629-41e0-ba73-f129af0cc68d",
	                    "status": "ASSOCIATING"
	                },
	                {
	                    "associatedEntity": "763721234306",
	                    "associationType": "PRINCIPAL",
	                    "external": true,
	                    "resourceShareArn": "arn:aws:ram:cn-easteast-1r:986293246532:resource-share/24048254-7629-41e0-ba73-f129af0cc68d",
	                    "status": "ASSOCIATING"
	                }
	            ]
	        },
	        "requestID": "78428a49-4222-446c-aff3-7167bc8838ea",
	        "eventID": "0fd3acf5-b013-45dc-aacf-ea925a89901f",
	        "readOnly": false,
	        "eventType": "AwsApiCall",
	        "managementEvent": true,
	        "recipientAccountId": "986293246532",
	        "eventCategory": "Management",
	        "tlsDetails": {
	            "tlsVersion": "TLSv1.3",
	            "cipherSuite": "TLS_AES_128_GCM_SHA256"
	        }
	    }
	]
	
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
