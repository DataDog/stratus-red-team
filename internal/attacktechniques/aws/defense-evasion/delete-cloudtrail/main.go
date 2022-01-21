package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.delete-cloudtrail",
		FriendlyName:       "Delete a CloudTrail Trail",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Delete a CloudTrail trail.

Warm-up: Creates a CloudTrail trail.

Detonation: Deletes the CloudTrail trail.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	cloudtrailClient := cloudtrail.NewFromConfig(providers.AWS().GetConnection())
	trailName := params["cloudtrail_trail_name"]

	log.Println("Deleting CloudTrail trail " + trailName)

	_, err := cloudtrailClient.DeleteTrail(context.Background(), &cloudtrail.DeleteTrailInput{
		Name: aws.String(trailName),
	})

	if err != nil {
		return errors.New("unable to delete CloudTrail logging: " + err.Error())
	}

	return nil
}

func revert(params map[string]string) error {
	cloudtrailClient := cloudtrail.NewFromConfig(providers.AWS().GetConnection())
	trailName := params["cloudtrail_trail_name"]

	log.Println("Restarting CloudTrail trail " + trailName)
	_, err := cloudtrailClient.StartLogging(context.Background(), &cloudtrail.StartLoggingInput{
		Name: aws.String(trailName),
	})

	return err
}
