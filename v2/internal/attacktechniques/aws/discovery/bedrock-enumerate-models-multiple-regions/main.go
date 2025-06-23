package aws

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.discovery.bedrock-enumerate-models-multiple-regions",
		FriendlyName: "Enumerate Bedrock models in multiple regions",
		Description: `
Simulates an attacker enumerating Bedrock models in multiple regions. Attackers frequently use this enumeration technique after having compromised an access key, to use it to answer their prompts.

Warm-up: None.

Detonation: 

- Perform <code>bedrock:InvokeModel</code> to check if bedrock model is available.
`,
		Detection: `
Through CloudTrail's <code>InvokeModel</code> events. 
These can be considered suspicious especially when performed by a long-lived access key, or when the calls span across multiple regions.
`,
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Discovery},
		Detonate:           detonate,
	})
}

type minimalPromptBody struct {
	Prompt            string `json:"prompt"`
	MaxTokensToSample int    `json:"max_tokens_to_sample"`
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	awsConnection := providers.AWS().GetConnection()
	regions := []string{"us-east-1", "us-west-2", "eu-west-2", "eu-west-3", "ap-northeast-2", "ap-southeast-2"}
	modelId := "anthropic.claude-3-sonnet-20240229-v1:0"

	log.Printf("Attempting to invoke Bedrock model %s in regions: %v", modelId, regions)

	requestBody := minimalPromptBody{
		Prompt:            "Human: story of dogs",
		MaxTokensToSample: 300,
	}
	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	for _, region := range regions {
		log.Printf("Attempting InvokeModel for %s in region: %s", modelId, region)

		regionalConfig := awsConnection.Copy()
		regionalConfig.Region = region
		bedrockClient := bedrockruntime.NewFromConfig(regionalConfig)

		params := &bedrockruntime.InvokeModelInput{
			ModelId:     aws.String(modelId),
			Body:        bodyBytes,
			ContentType: aws.String("application/json"),
			Accept:      aws.String("*/*"),
		}

		_, invokeErr := bedrockClient.InvokeModel(context.Background(), params)
		if invokeErr != nil {
			log.Printf("Error invoking model %s in region %s: %v.", modelId, region, invokeErr)
		} else {
			log.Printf("Successfully invoked model %s in region %s (or the call was accepted without immediate error).", modelId, region)
		}
	}
	log.Println("Finished InvokeModel attempts across regions.")
	return nil
}
