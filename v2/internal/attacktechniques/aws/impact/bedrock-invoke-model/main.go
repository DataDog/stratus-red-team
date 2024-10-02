package aws

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"

	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go/aws"
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.impact.bedrock-invoke-model",
		FriendlyName: "Invoke Bedrock Model",
		Description: `
Simulates an attacker enumerating Bedrock models and then invoking Anthropic Claude 2 to run inference using the provided prompt. LLMjacking is an attack vector where attackers use stolen cloud credentials to run large language models, leading to unauthorized inference. This technique demonstrates how attackers can use Bedrock to run inference on Anthropic Claude 2 to generate responses to prompts.

Warm-up: None.

Detonation: 

- Perform <code>bedrock:ListFoundationModels</code> to enumerate foundation models that can be used in the current region.
- Perform <code>bedrock:InvokeModel</code> to invoke Claude 2.

References:

- https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/
- https://sysdig.com/blog/growing-dangers-of-llmjacking/
- https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf
`,
		Detection: `
Through CloudTrail's <code>ListFoundationModels</code> and <code>InvokeModel</code> events. 
If model invocation logging is enabled, invocations requests are logged on CloudWatch and/or S3 buckets with additional details, including prompt content and response. This greatly helps in detecting malicious invocations.
`,
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Impact},
		Detonate:           detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	awsConnection := providers.AWS().GetConnection()
	bedrockClient := bedrock.NewFromConfig(awsConnection)

	log.Println("Listing foundation models available in the current region")
	var models []types.FoundationModelSummary
	result, err := bedrockClient.ListFoundationModels(context.Background(), &bedrock.ListFoundationModelsInput{})

	if err != nil {
		log.Printf("Couldn't list foundation models. Here's why: %v\n", err)
	} else {
		models = result.ModelSummaries
		log.Println("The following foundation models can be used:")
		for _, modelSummary := range models {
			log.Println(*modelSummary.ModelId)
		}
	}

	log.Println("Invoking Anthropic Claude 2")
	wrapper := InvokeModelWrapper{BedrockRuntimeClient: bedrockruntime.NewFromConfig(awsConnection)}
	prompt := "Are you Turing complete?"
	completion, err := wrapper.InvokeModel(prompt)
	if err != nil {
		log.Fatal("failed to invoke model", err)
	} else {
		log.Println("Prompt:", prompt)
		log.Println("Response:", completion)
	}

	return nil
}

type InvokeModelWrapper struct {
	BedrockRuntimeClient *bedrockruntime.Client
}

type ClaudeRequest struct {
	Prompt            string `json:"prompt"`
	MaxTokensToSample int    `json:"max_tokens_to_sample"`
	// Omitting optional request parameters
}

type ClaudeResponse struct {
	Completion string `json:"completion"`
}

func (wrapper InvokeModelWrapper) InvokeModel(prompt string) (string, error) {
	modelId := "anthropic.claude-v2"

	// Anthropic Claude requires enclosing the prompt as follows:
	enclosedPrompt := "Human: " + prompt + "\n\nAssistant:"

	body, err := json.Marshal(ClaudeRequest{
		Prompt:            enclosedPrompt,
		MaxTokensToSample: 1, // Set to minimum to reduce costs
	})

	if err != nil {
		log.Fatal("failed to marshal", err)
	}

	output, err := wrapper.BedrockRuntimeClient.InvokeModel(context.TODO(), &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(modelId),
		ContentType: aws.String("application/json"),
		Body:        body,
	})

	if err != nil {
		fmt.Printf("Error: Couldn't invoke Anthropic Claude. Here's why: %v\n", err)
	}

	var response ClaudeResponse
	if err := json.Unmarshal(output.Body, &response); err != nil {
		log.Fatal("failed to unmarshal", err)
	}

	return response.Completion, nil
}
