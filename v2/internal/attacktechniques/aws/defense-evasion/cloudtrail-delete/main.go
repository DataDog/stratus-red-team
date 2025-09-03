package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
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
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "Impair Defenses: Disable Cloud Logs",
						ID:   "T1562.008",
						URL:  "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1562.008.html",
					},
				},
			},
		},
		Description: `
Delete a CloudTrail trail. Simulates an attacker disrupting CloudTrail logging.

Warm-up: 

- Create a CloudTrail trail.

Detonation: 

- Delete the CloudTrail trail.
`,
		Detection: `
Identify when a CloudTrail trail is deleted, through CloudTrail's <code>DeleteTrail</code> event.

GuardDuty also provides a dedicated finding type, [Stealth:IAMUser/CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#stealth-iam-cloudtrailloggingdisabled).
`,
		IsIdempotent:               false, // can't delete a CloudTrail twice
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
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
