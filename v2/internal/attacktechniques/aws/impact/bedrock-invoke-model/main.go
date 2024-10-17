package aws

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

const BedrockModelID = "anthropic.claude-3-sonnet-20240229-v1:0"
const BedrockModelFullName = "Anthropic Claude 3 Sonnet"
const EnvVarCustomModel = "STRATUS_RED_TEAM_BEDROCK_MODEL"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.impact.bedrock-invoke-model",
		FriendlyName: "Invoke Bedrock Model",
		Description: `
Simulates an attacker enumerating Bedrock models and then invoking the ` + BedrockModelFullName + ` model to run inference using an arbitrary prompt. LLMjacking is an attack vector where attackers use stolen cloud credentials to run large language models, leading to unauthorized inference.

Warm-up: None.

Detonation: 

- Enumerate foundation models that can be used in the current region using <code>bedrock:ListFoundationModels</code>.
- If ` + BedrockModelFullName + ` (` + BedrockModelID + `) is not enabled, attempt to enable it using <code>bedrock:PutUseCaseForModelAccess</code>, <code>bedrock:ListFoundationModelAgreementOffers</code>, <code>bedrock:CreateFoundationModelAgreement</code>, <code>bedrock:PutFoundationModelEntitlement</code>
- Call <code>bedrock:InvokeModel</code> to run inference using the model.

References:

- https://permiso.io/blog/exploiting-hosted-models
- https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/
- https://sysdig.com/blog/growing-dangers-of-llmjacking/
- https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf

!!! note

	This technique attempts to enable and invoke the Bedrock model ` + BedrockModelID + `. To do this, it creates a Bedrock use case request for Anthropic models with a fictitious company nam, website and use-case:

	` + "a" + `

	It is expected that this will cause AWS to automatically send you an email entitled <code>You accepted an AWS Marketplace offer</code>. 
	Only Anthropic models require this. 
	If you want to use a different model, you can set the ` + EnvVarCustomModel + ` environment variable to the model ID you want to use (see the list [here](https://docs.aws.amazon.com/bedrock/latest/userguide/model-ids.html)), and make sure it's available in your current region.

!!! note

	After enabling it, Stratus Red Team will not disable the Bedrock model ` + BedrockModelID + `.
	While this should not incur any additional costs, you can disable the model by going to the [Model Access](https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/modelaccess) page in the AWS Management Console.
`,
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Impact},
		Detonate:           detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	awsConnection := providers.AWS().GetConnection()

	model, err := findAndEnableModelToUse(awsConnection)
	if err != nil {
		return fmt.Errorf("unable to find a model to use: %w", err)
	}
	log.Println("Invoking " + model)
	wrapper := BedrockInvoker{BedrockRuntimeClient: bedrockruntime.NewFromConfig(awsConnection), ModelID: model}
	prompt := "Respond with: Hello, this is (your model) from Bedrock!"
	result, err := wrapper.InvokeModel(prompt)
	if err != nil {
		return fmt.Errorf("unable to invoke Bedrock model: %w", err)
	}
	log.Println("Successfully invoked Bedrock model. Response: " + result)
	return nil
}

func findAndEnableModelToUse(awsConnection aws.Config) (string, error) {
	var modelToUse string
	if model := os.Getenv(EnvVarCustomModel); model != "" {
		modelToUse = model
	} else {
		modelToUse = BedrockModelID
	}

	log.Println("Retrieving model availability for " + modelToUse)
	availability, err := GetFoundationModelAvailability(awsConnection, modelToUse)
	if err != nil {
		return "", fmt.Errorf("unable to get model availability info for %s: %w", modelToUse, err)
	}
	if availability.RegionAvailability != "AVAILABLE" {
		return "", errors.New("Bedrock model " + modelToUse + " is not available in the current region. Try setting AWS_REGION=us-east-1 instead")
	}
	if availability.EntitlementAvailability != "AVAILABLE" {
		err := enableModel(awsConnection, modelToUse, availability)
		if err != nil {
			return "", fmt.Errorf("unable to enable model: %w", err)
		}
	}
	return modelToUse, nil
}

func enableModel(awsConnection aws.Config, modelId string, availability *BedrockModelAvailability) error {
	log.Println("Enabling model " + modelId)

	// Need to create a use-case request for Anthropic models
	// AgreementAvailability is account-wide (not region-specific). If a use-case was put for the model once in the account, it will be available in all regions, and we'll only need to call PutFoundationModelEntitlement in further region
	if availability.AgreementAvailability.Status != "AVAILABLE" {
		if strings.HasPrefix(modelId, "anthropic.") && availability.AgreementAvailability.Status != "AVAILABLE" {
			_, err := PutUseCaseForModelAccess(awsConnection, &BedrockUseCaseRequest{
				CompanyName:         "test",
				CompanyWebsite:      "https://test.com",
				IntendedUsers:       "0",
				IndustryOption:      "Government",
				OtherIndustryOption: "",
				UseCases:            "None of the Above. test",
			})
			if err != nil {
				return fmt.Errorf("unable to put use case for model access: %w", err)
			}
		}

		offerToken, err := ListFoundationModelAgreementOffers(awsConnection, modelId)
		if err != nil {
			return fmt.Errorf("unable to list agreement offers: %w", err)
		}

		_, err = CreateFoundationModelAgreement(awsConnection, modelId, offerToken)
		if err != nil {
			return fmt.Errorf("unable to create model agreement: %w", err)
		}
	}

	_, err := PutFoundationModelEntitlement(awsConnection, modelId)
	if err != nil {
		return fmt.Errorf("unable to put model entitlement: %w", err)
	}
	log.Println("Successfully enabled model, waiting for it to become available")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return WaitForModelToBecomeAvailable(ctx, awsConnection, modelId)

}

type BedrockModelAvailability struct {
	RegionAvailability    string `json:"regionAvailability"`
	AgreementAvailability struct {
		Status string `json:"status"`
	} `json:"agreementAvailability"`
	EntitlementAvailability string `json:"entitlementAvailability"`
}

// GetFoundationModelAvailability retrieves model availability information.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func GetFoundationModelAvailability(cfg aws.Config, model string) (*BedrockModelAvailability, error) {
	region := cfg.Region

	host := fmt.Sprintf("bedrock.%s.amazonaws.com", region)
	endpoint := fmt.Sprintf("https://%s/foundation-model-availability/%s", host, model)

	credentials, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return nil, errors.New("Error retrieving credentials: " + err.Error())
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, errors.New("Error creating request: " + err.Error())
	}

	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // For GET requests, the payload is always an empty string
	req.Host = host
	signer := v4.NewSigner()
	if err = signer.SignHTTP(context.Background(), credentials, req, payloadHash, "bedrock", region, time.Now()); err != nil {
		return nil, errors.New("Error signing request: " + err.Error())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Error making request: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("Response error: " + resp.Status)
	}

	body, err := io.ReadAll(io.Reader(resp.Body))
	if err != nil {
		return nil, errors.New("Error reading response body: " + err.Error())
	}

	fmt.Println(string(body))
	var result BedrockModelAvailability
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.New("Error unmarshalling response body: " + err.Error())
	}
	return &result, nil
}

// ListFoundationModelAgreementOffers retrieves information about the agreement offers for the provided model.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func ListFoundationModelAgreementOffers(cfg aws.Config, model string) (string, error) {
	region := cfg.Region
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // For GET requests, the payload is always an empty string

	host := fmt.Sprintf("bedrock.%s.amazonaws.com", region)
	endpoint := fmt.Sprintf("https://%s/list-foundation-model-agreement-offers/%s", host, model)

	credentials, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return "", errors.New("Error retrieving credentials: " + err.Error())
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", errors.New("Error creating request: " + err.Error())
	}

	req.Host = host
	signer := v4.NewSigner()
	if err = signer.SignHTTP(context.Background(), credentials, req, payloadHash, "bedrock", region, time.Now()); err != nil {
		return "", errors.New("Error signing request: " + err.Error())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("Error making request: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("Response error: " + resp.Status)
	}

	body, err := io.ReadAll(io.Reader(resp.Body))
	if err != nil {
		return "", errors.New("Error reading response body: " + err.Error())
	}

	var offers struct {
		Offers []struct {
			OfferToken string `json:"offerToken"`
		} `json:"offers"`
	}

	if err := json.Unmarshal(body, &offers); err != nil {
		return "", errors.New("Error unmarshalling response body: " + err.Error())
	}

	if len(offers.Offers) == 0 {
		return "", errors.New("no offers found")
	}

	offerToken := offers.Offers[0].OfferToken

	return offerToken, nil
}

// CreateUseCaseForModelAccess TODO
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
type BedrockUseCaseRequest struct {
	CompanyName         string `json:"companyName"`
	CompanyWebsite      string `json:"companyWebsite"`
	IntendedUsers       string `json:"intendedUsers"`
	IndustryOption      string `json:"industryOption"`
	OtherIndustryOption string `json:"otherIndustryOption"`
	UseCases            string `json:"useCases"`
}

func PutUseCaseForModelAccess(cfg aws.Config, bedrockUseCase *BedrockUseCaseRequest) (string, error) {
	region := cfg.Region

	bedrockUseCasePayload, err := json.Marshal(bedrockUseCase)
	if err != nil {
		return "", errors.New("Error marshalling JSON: " + err.Error())
	}

	payload := map[string]string{
		"formData": base64.StdEncoding.EncodeToString(bedrockUseCasePayload),
	}
	jsonPayload, _ := json.Marshal(payload)
	payloadHash := utils.SHA256Hash(string(jsonPayload))

	host := fmt.Sprintf("bedrock.%s.amazonaws.com", region)
	endpoint := fmt.Sprintf("https://%s/use-case-for-model-access", host)

	credentials, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		fmt.Printf("Error retrieving credentials: %v", err)
		return "", err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		fmt.Printf("Error creating request: %v", err)
		return "", err
	}

	req.Host = host
	signer := v4.NewSigner()
	if err = signer.SignHTTP(context.Background(), credentials, req, payloadHash, "bedrock", region, time.Now()); err != nil {
		fmt.Printf("Error signing request: %v", err)
		return "", err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request: %v", err)
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.Reader(resp.Body))
	if err != nil {
		fmt.Printf("Error reading response body: %v", err)
		return "", err
	}

	bodyString := string(body)
	if resp.StatusCode != 201 {
		return "", fmt.Errorf("unexpected HTTP response code %d when creating use-case for model access. Response: %s", bodyString, resp.Status)
	}

	return bodyString, nil
}

// CreateFoundationModelAgreement requests access to the model by defining a subscription agreement in AWS Marketplace.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func CreateFoundationModelAgreement(cfg aws.Config, model string, offerToken string) (string, error) {
	region := cfg.Region

	payload := map[string]string{
		"modelId":    model,
		"offerToken": offerToken,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", errors.New("Error unmarshalling JSON: " + err.Error())
	}

	payloadHash := utils.SHA256Hash(string(jsonPayload))

	host := fmt.Sprintf("bedrock.%s.amazonaws.com", region)
	endpoint := fmt.Sprintf("https://%s/create-foundation-model-agreement", host)

	credentials, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return "", errors.New("Error retrieving credentials: " + err.Error())
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		return "", errors.New("Error creating request: " + err.Error())
	}

	req.Host = host
	signer := v4.NewSigner()
	if err = signer.SignHTTP(context.Background(), credentials, req, payloadHash, "bedrock", region, time.Now()); err != nil {
		return "", errors.New("Error signing request: " + err.Error())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("Error making request: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("Response error: " + resp.Status)
	}

	body, err := io.ReadAll(io.Reader(resp.Body))
	if err != nil {
		return "", errors.New("Error reading response body: " + err.Error())
	}

	return string(body), nil
}

// PutFoundationModelEntitlement enables the entitlement for the model.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func PutFoundationModelEntitlement(cfg aws.Config, model string) (string, error) {
	region := cfg.Region

	payload := map[string]string{
		"modelId": model,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", errors.New("Error unmarshalling JSON: " + err.Error())
	}

	payloadHash := utils.SHA256Hash(string(jsonPayload))

	host := fmt.Sprintf("bedrock.%s.amazonaws.com", region)
	endpoint := fmt.Sprintf("https://%s/foundation-model-entitlement", host)

	credentials, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return "", errors.New("Error retrieving credentials: " + err.Error())
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		return "", errors.New("Error creating request: " + err.Error())
	}

	req.Host = host
	signer := v4.NewSigner()
	if err = signer.SignHTTP(context.Background(), credentials, req, payloadHash, "bedrock", region, time.Now()); err != nil {
		return "", errors.New("Error signing request: " + err.Error())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("Error making request: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("Response error: " + resp.Status)
	}

	body, err := io.ReadAll(io.Reader(resp.Body))
	if err != nil {
		return "", errors.New("Error reading response body: " + err.Error())
	}

	return string(body), nil
}

func WaitForModelToBecomeAvailable(ctx context.Context, sdkConfig aws.Config, model string) error {
	const RetryInterval = 10 * time.Second
	ticker := time.NewTicker(RetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			availabilityResponse, err := GetFoundationModelAvailability(sdkConfig, model)
			if err != nil {
				return fmt.Errorf("unable to get model availability info for %s: %w", model, err)
			}
			if availabilityResponse.AgreementAvailability.Status == "AVAILABLE" {
				log.Println("The model is now ready to use!")
				return nil
			} else {
				log.Println("The agreement is not available yet, retrying in " + RetryInterval.String())
			}
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for model %s to become available", model)
		}

	}
}

type BedrockInvoker struct {
	ModelID              string
	BedrockRuntimeClient *bedrockruntime.Client
}

// https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-anthropic-claude-messages.html#api-inference-examples-claude-messages-code-examples

type ClaudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type ClaudeMessageRequest struct {
	AnthropicVersion  string          `json:"anthropic_version"`
	MaxTokensToSample int             `json:"max_tokens"`
	SystemPrompt      string          `json:"system"`
	Messages          []ClaudeMessage `json:"messages"`
}
type ClaudeResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func (w *BedrockInvoker) InvokeModel(prompt string) (string, error) {
	body, err := json.Marshal(ClaudeMessageRequest{
		AnthropicVersion:  "bedrock-2023-05-31",
		MaxTokensToSample: 100,
		SystemPrompt:      "Respond what the user tells you.",
		Messages:          []ClaudeMessage{{Role: "user", Content: prompt}},
	})

	if err != nil {
		return "", errors.New("failed to marshal: " + err.Error())
	}

	output, err := w.BedrockRuntimeClient.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
		ModelId:     &w.ModelID,
		ContentType: aws.String("application/json"),
		Body:        body,
	})

	if err != nil {
		return "", errors.New("failed to invoke model: " + err.Error())
	}

	var claudeResponse ClaudeResponse
	if err := json.Unmarshal(output.Body, &claudeResponse); err != nil {
		return "", errors.New("failed to unmarshal Bedrock response: " + err.Error())
	}

	return claudeResponse.Content[0].Text, nil
}
