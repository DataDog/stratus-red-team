package aws

import (
	"context"
	_ "embed"
	"errors"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.bedrock-guardrail-delete",
		FriendlyName:       "Delete Bedrock Guardrail",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Delete an Amazon Bedrock guardrail. Simulates an attacker disrupting AI safety controls.

Warm-up: 

- Create a Bedrock guardrail.

Detonation: 

- Delete the Bedrock guardrail.
`,
		Detection: `
Identify when a Bedrock guardrail is deleted, through CloudTrail's <code>DeleteModelGuardrail</code> event.
`,
		IsIdempotent:               false, // can't delete a guardrail twice
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bedrockClient := bedrock.NewFromConfig(providers.AWS().GetConnection())
	guardrailID := params["bedrock_guardrail_id"]

	log.Println("Deleting Bedrock guardrail " + guardrailID)

	_, err := bedrockClient.DeleteGuardrail(context.Background(), &bedrock.DeleteGuardrailInput{
		GuardrailIdentifier: &guardrailID,
	})

	if err != nil {
		return errors.New("unable to delete Bedrock guardrail: " + err.Error())
	}

	return nil
}
