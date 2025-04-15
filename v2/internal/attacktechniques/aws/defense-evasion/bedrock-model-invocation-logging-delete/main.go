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
		ID:                 "aws.defense-evasion.bedrock-model-invocation-logging-delete",
		FriendlyName:       "Delete Bedrock Model Invocation Logging",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Delete Amazon Bedrock model invocation logging configuration. Simulates an attacker disrupting AI activity monitoring.

WARNING: Only one model invocation logging configuration is allowed per region. This technique runs in ca-central-1 by default.
If you use ca-central-1 for production Bedrock usage, you should modify the region in both main.tf and main.go before running this technique.

Warm-up: 

- Create a Bedrock model invocation logging configuration.

Detonation: 

- Delete the Bedrock model invocation logging configuration.
`,
		Detection: `
Identify when Bedrock model invocation logging is deleted, through CloudTrail's <code>DeleteModelInvocationLogging</code> event.
`,
		IsIdempotent:               false, // can't delete logging config twice
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	// Get the base AWS configuration
	cfg := providers.AWS().GetConnection()

	// Override the region to ca-central-1 to match the Terraform configuration
	cfg.Region = "ca-central-1"

	bedrockClient := bedrock.NewFromConfig(cfg)
	loggingConfigID := params["bedrock_logging_config_id"]

	log.Println("Deleting Bedrock model invocation logging configuration " + loggingConfigID + " in region ca-central-1")

	_, err := bedrockClient.DeleteModelInvocationLoggingConfiguration(context.Background(), &bedrock.DeleteModelInvocationLoggingConfigurationInput{})

	if err != nil {
		return errors.New("unable to delete Bedrock model invocation logging configuration: " + err.Error())
	}

	return nil
}
