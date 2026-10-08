package aws

import (
	_ "embed"

	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.ec2-share-ebs-volume",
		FriendlyName:       "Exfiltrate EBS Volume by Sharing It Through RAM",
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "",
						ID:   "",
						URL:  "",
					},
				},
			},
		},
		Description: `
Exfiltrates an EBS volume by sharing it with an external AWS account.

Warm-up:

- Create an EBS volume
- Create a RAM resource share

Detonation:

- Call ram:AssociateResourceShare to share the EBS volume with an external, fictitious AWS account
`,
		Detection:                  ``,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var ShareWithAccountId = "012345678912"

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	// associate the EBS volume with the RAM resource share
	ramClient := ram.NewFromConfig(providers.AWS().GetConnection())

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	return nil
}
