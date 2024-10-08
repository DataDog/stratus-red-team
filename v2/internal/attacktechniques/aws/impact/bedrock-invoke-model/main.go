package aws

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
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

- https://permiso.io/blog/exploiting-hosted-models
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
		return fmt.Errorf("couldn't list foundation models: %w", err)
	}
	models = result.ModelSummaries
	log.Println("The following foundation models can be used:")
	for _, modelSummary := range models {
		log.Println(*modelSummary.ModelId)
	}

	log.Println("Retrieving the availability information of Anthropic Claude 2")
	response, err := GetFoundationModelAvailability(awsConnection, "anthropic.claude-v2")
	if err != nil {
		fmt.Println("Error making API request:", err)
	}
	fmt.Println("Model availability info:", response)

	log.Println("Invoking Anthropic Claude 2")
	wrapper := invokeModelWrapper{BedrockRuntimeClient: bedrockruntime.NewFromConfig(awsConnection)}
	prompt := "Are you Turing complete?"
	_, err = wrapper.InvokeModel(prompt)
	if err != nil {
		return fmt.Errorf("unable to invoke Bedrock model: %w", err)
	}
	log.Println("Successfully invoked Bedrock model")
	return nil
}

func GetFoundationModelAvailability(cfg aws.Config, model string) (string, error) {
	region := cfg.Region

	model = replaceColon(model)
	host := fmt.Sprintf("bedrock.%s.amazonaws.com", region)
	endpoint := fmt.Sprintf("https://%s/foundation-model-availability/%s", host, model)

	credentials, err := cfg.Credentials.Retrieve(context.TODO())
	if err != nil {
		return "", errors.New("Error retrieving credentials: " + err.Error())
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", errors.New("Error creating request: " + err.Error())
	}

	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // For GET requests, the payload is always an empty string
	req.Host = host
	signer := v4.NewSigner()
	if err = signer.SignHTTP(context.TODO(), credentials, req, payloadHash, "bedrock", region, time.Now()); err != nil {
		return "", errors.New("Error signing request: " + err.Error())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("Error making request: " + err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.Reader(resp.Body))
	if err != nil {
		return "", errors.New("Error reading response body: " + err.Error())
	}

	return string(body), nil
}

func replaceColon(input string) string {
	return strings.ReplaceAll(input, ":", "%3A")
}

type invokeModelWrapper struct {
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

func (wrapper invokeModelWrapper) InvokeModel(prompt string) (string, error) {
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
