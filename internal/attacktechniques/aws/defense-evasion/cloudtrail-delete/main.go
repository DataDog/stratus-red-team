package aws

import (
	"context"
	_ "embed"
	"errors"
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
		ID:                 "aws.defense-evasion.cloudtrail-delete",
		FriendlyName:       "Delete CloudTrail Trail",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Delete a CloudTrail trail. Simulates an attacker disrupting CloudTrail logging.

Warm-up: 

- Create a CloudTrail trail.

Detonation: 

- Delete the CloudTrail trail.
`,
		IsIdempotent:               false, // can't delete a CloudTrail twice
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	cloudtrailClient := cloudtrail.NewFromConfig(providers.AWS().GetConnection())
	trailName := params["cloudtrail_trail_name"]

	log.Println("Deleting CloudTrail trail " + trailName)

	_, err := cloudtrailClient.DeleteTrail(context.Background(), &cloudtrail.DeleteTrailInput{
		Name: &trailName,
	})

	if err != nil {
		return errors.New("unable to delete CloudTrail logging: " + err.Error())
	}

	return nil
}
