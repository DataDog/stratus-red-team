package aws

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

const BedrockModelID = "anthropic.claude-3-sonnet-20240229-v1:0"
const BedrockModelFullName = "Anthropic Claude 3 Sonnet"
const EnvVarCustomModel = "STRATUS_RED_TEAM_BEDROCK_MODEL"

var bedrockUseCaseRequest = BedrockUseCaseRequest{
	CompanyName:         "test",
	CompanyWebsite:      "https://test.com",
	IntendedUsers:       "0",
	IndustryOption:      "Government",
	OtherIndustryOption: "",
	UseCases:            "None of the Above. test",
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.impact.bedrock-invoke-model",
		FriendlyName: "Invoke Bedrock Model",
		Description: `
Simulates an attacker enumerating Bedrock models and then invoking the ` + BedrockModelFullName + ` (<code>` + BedrockModelID + `</code>) model to run inference using an arbitrary prompt. LLMjacking is an attack vector where attackers use stolen cloud credentials to run large language models, leading to unauthorized inference.

Warm-up: None.

Detonation: 

- If ` + BedrockModelFullName + ` is not enabled, attempt to enable it using <code>PutUseCaseForModelAccess</code>, <code>ListFoundationModelAgreementOffers</code>, <code>CreateFoundationModelAgreement</code>, <code>PutFoundationModelEntitlement</code>
- Call <code>bedrock:InvokeModel</code> to run inference using the model.

References:

- https://permiso.io/blog/exploiting-hosted-models
- https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/
- https://sysdig.com/blog/growing-dangers-of-llmjacking/
- https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf

!!! note

	This technique attempts to enable and invoke the Bedrock model ` + BedrockModelID + `. To do this, it creates a Bedrock use case request for Anthropic models with a fictitious company name, website and use-case:

	- Company Name: <code>` + bedrockUseCaseRequest.CompanyName + `</code>
	- Company Website: <code>` + bedrockUseCaseRequest.CompanyWebsite + `</code>
	- Intended Users: <code>` + bedrockUseCaseRequest.IntendedUsers + `</code>
	- Industry Option: <code>` + bedrockUseCaseRequest.IndustryOption + `</code>
	- Use Cases: <code>` + bedrockUseCaseRequest.UseCases + `</code>


	It is expected that this will cause AWS to automatically send you an email entitled <code>You accepted an AWS Marketplace offer</code>. If you want to use a different Anthropic model, you can set the <code>` + EnvVarCustomModel + `</code> environment variable to the model ID you want to use (see the list [here](https://docs.aws.amazon.com/bedrock/latest/userguide/model-ids.html)). Since the inputs to <code>InvokeModel</code> are model-specific, you can only specify an Anthropic model:

	- <code>anthropic.claude-v2</code>
	- <code>anthropic.claude-v2:1</code>
	- <code>anthropic.claude-3-sonnet-20240229-v1:0</code> (default)
	- <code>anthropic.claude-3-5-sonnet-20240620-v1:0</code>
	- <code>anthropic.claude-3-haiku-20240307-v1:0</code>
	- <code>anthropic.claude-instant-v1</code>


!!! note

	After enabling it, Stratus Red Team will not disable the Bedrock model.	While this should not incur any additional costs, you can disable the model by going to the [Model Access](https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/modelaccess) page in the AWS Management Console.
`,
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Impact},
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
		Detonate: detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	awsConnection := providers.AWS().GetConnection()

	var modelToUse string
	if model := os.Getenv(EnvVarCustomModel); model != "" {
		modelToUse = model
	} else {
		modelToUse = BedrockModelID
	}

	bedrockClient := CustomBedrockClient{
		BedrockRuntimeClient: bedrockruntime.NewFromConfig(awsConnection),
		ModelID:              modelToUse,
		awsConfig:            awsConnection,
		UserAgent:            useragent.GetStratusUserAgentForUUID(providers.AWS().UniqueCorrelationId),
	}

	if err := bedrockClient.EnsureModelEnabled(); err != nil {
		return fmt.Errorf("unable to find a model to use: %w", err)
	}
	log.Println("Invoking " + bedrockClient.ModelID)
	prompt := "Respond with: Hello, this is (your model) from Bedrock!"
	result, err := bedrockClient.InvokeModel(prompt)
	if err != nil {
		return fmt.Errorf("unable to invoke Bedrock model: %w", err)
	}
	log.Println("Successfully invoked Bedrock model. Response: " + result)
	return nil
}

type CustomBedrockClient struct {
	ModelID              string
	BedrockRuntimeClient *bedrockruntime.Client
	awsConfig            aws.Config
	UserAgent            string
}

type BedrockUseCaseRequest struct {
	CompanyName         string `json:"companyName"`
	CompanyWebsite      string `json:"companyWebsite"`
	IntendedUsers       string `json:"intendedUsers"`
	IndustryOption      string `json:"industryOption"`
	OtherIndustryOption string `json:"otherIndustryOption"`
	UseCases            string `json:"useCases"`
}

type GetFoundationModelAvailabilityResponse struct {
	RegionAvailability    string `json:"regionAvailability"`
	AgreementAvailability struct {
		Status       string `json:"status"`
		ErrorMessage string `json:"errorMessage"`
	} `json:"agreementAvailability"`
	EntitlementAvailability string `json:"entitlementAvailability"`
}

func (m *CustomBedrockClient) EnsureModelEnabled() error {
	log.Println("Retrieving model availability for " + m.ModelID)
	availability, err := m.GetFoundationModelAvailability()
	if err != nil {
		return fmt.Errorf("unable to get model availability info for %s: %w", m.ModelID, err)
	}
	if availability.RegionAvailability != "AVAILABLE" {
		return errors.New("Bedrock model " + m.ModelID + " is not available in the current region. Try setting AWS_REGION=us-east-1 instead")
	}
	if availability.EntitlementAvailability != "AVAILABLE" {
		err := m.enableModel(availability)
		if err != nil {
			return fmt.Errorf("unable to enable model: %w", err)
		}
	}
	return nil
}

func (m *CustomBedrockClient) enableModel(availability *GetFoundationModelAvailabilityResponse) error {
	log.Println("Enabling model " + m.ModelID)

	// Need to create a use-case request for Anthropic models
	// AgreementAvailability is account-wide (not region-specific). If a use-case was put for the model once in the account, it will be available in all regions, and we'll only need to call PutFoundationModelEntitlement in further region
	if availability.AgreementAvailability.Status != "AVAILABLE" {
		if strings.HasPrefix(m.ModelID, "anthropic.") && availability.AgreementAvailability.Status != "AVAILABLE" {
			_, err := m.PutUseCaseForModelAccess(&bedrockUseCaseRequest)
			if err != nil {
				return fmt.Errorf("unable to put use case for model access: %w", err)
			}
		}

		offerToken, err := m.ListFoundationModelAgreementOffers()
		if err != nil {
			return fmt.Errorf("unable to list agreement offers: %w", err)
		}

		_, err = m.CreateFoundationModelAgreement(offerToken)
		if err != nil {
			return fmt.Errorf("unable to create model agreement: %w", err)
		}
	}

	_, err := m.PutFoundationModelEntitlement()
	if err != nil {
		return fmt.Errorf("unable to put model entitlement: %w", err)
	}
	log.Println("Successfully enabled model, waiting for it to become available. This can take a few minutes.")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return m.waitForModelToBecomeAvailable(ctx)

}

// GetFoundationModelAvailability retrieves model availability information.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func (m *CustomBedrockClient) GetFoundationModelAvailability() (*GetFoundationModelAvailabilityResponse, error) {
	endpoint := fmt.Sprintf("https://bedrock.%s.amazonaws.com/foundation-model-availability/%s", m.awsConfig.Region, m.ModelID)
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Empty payload hash for GET

	body, err := m.executeRequest("GET", endpoint, nil, payloadHash)
	if err != nil {
		return nil, err
	}

	var result GetFoundationModelAvailabilityResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("GetFoundationModelAvailability failed: %w", err)
	}
	return &result, nil
}

// ListFoundationModelAgreementOffers retrieves information about the agreement offers for the provided model.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func (m *CustomBedrockClient) ListFoundationModelAgreementOffers() (string, error) {
	endpoint := fmt.Sprintf("https://bedrock.%s.amazonaws.com/list-foundation-model-agreement-offers/%s", m.awsConfig.Region, m.ModelID)
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // Empty payload hash for GET

	body, err := m.executeRequest("GET", endpoint, nil, payloadHash)
	if err != nil {
		return "", err
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

	return offers.Offers[0].OfferToken, nil
}

// PutUseCaseForModelAccess submits a use case for model access.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func (m *CustomBedrockClient) PutUseCaseForModelAccess(bedrockUseCase *BedrockUseCaseRequest) (string, error) {
	bedrockUseCasePayload, err := json.Marshal(bedrockUseCase)
	if err != nil {
		return "", errors.New("Error marshalling JSON: " + err.Error())
	}

	payloadBytes, err := json.Marshal(map[string]string{
		"formData": base64.StdEncoding.EncodeToString(bedrockUseCasePayload),
	})
	if err != nil {
		return "", errors.New("Error marshalling JSON: " + err.Error())
	}

	payloadHash := utils.SHA256Hash(string(payloadBytes))
	endpoint := fmt.Sprintf("https://bedrock.%s.amazonaws.com/use-case-for-model-access", m.awsConfig.Region)

	body, err := m.executeRequest("POST", endpoint, payloadBytes, payloadHash)
	if err != nil {
		return "", fmt.Errorf("PutUseCaseForModelAccess failed: %w", err)
	}

	return string(body), nil
}

// CreateFoundationModelAgreement requests access to the model by defining a subscription agreement in AWS Marketplace.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func (m *CustomBedrockClient) CreateFoundationModelAgreement(offerToken string) (string, error) {
	payloadBytes, err := json.Marshal(map[string]string{
		"modelId":    m.ModelID,
		"offerToken": offerToken,
	})
	if err != nil {
		return "", errors.New("Error marshalling JSON: " + err.Error())
	}

	payloadHash := utils.SHA256Hash(string(payloadBytes))
	endpoint := fmt.Sprintf("https://bedrock.%s.amazonaws.com/create-foundation-model-agreement", m.awsConfig.Region)

	body, err := m.executeRequest("POST", endpoint, payloadBytes, payloadHash)
	if err != nil {
		return "", fmt.Errorf("CreateFoundationModelAgreement failed: %w", err)
	}

	return string(body), nil
}

// PutFoundationModelEntitlement enables the entitlement for the model.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func (m *CustomBedrockClient) PutFoundationModelEntitlement() (string, error) {
	payloadBytes, err := json.Marshal(map[string]string{
		"modelId": m.ModelID,
	})
	if err != nil {
		return "", errors.New("Error marshalling JSON: " + err.Error())
	}

	payloadHash := utils.SHA256Hash(string(payloadBytes))
	endpoint := fmt.Sprintf("https://bedrock.%s.amazonaws.com/foundation-model-entitlement", m.awsConfig.Region)

	body, err := m.executeRequest("POST", endpoint, payloadBytes, payloadHash)
	if err != nil {
		return "", fmt.Errorf("PutFoundationModelEntitlement failed: %w", err)
	}

	return string(body), nil
}

func (m *CustomBedrockClient) waitForModelToBecomeAvailable(ctx context.Context) error {
	const RetryInterval = 10 * time.Second
	ticker := time.NewTicker(RetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			availabilityResponse, err := m.GetFoundationModelAvailability()
			if err != nil {
				return fmt.Errorf("unable to get model availability info for %s: %w", m.ModelID, err)
			}
			if availabilityResponse.AgreementAvailability.Status == "AVAILABLE" {
				log.Println("The model is now ready to use!")
				return nil
			} else if availabilityResponse.AgreementAvailability.ErrorMessage != "" {
				return fmt.Errorf("error enabling model: %s", availabilityResponse.AgreementAvailability.ErrorMessage)
			} else {
				log.Println("The agreement is not available yet, retrying in " + RetryInterval.String())
			}
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for model %s to become available", m.ModelID)
		}

	}
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

func (m *CustomBedrockClient) InvokeModel(prompt string) (string, error) {
	body, err := json.Marshal(ClaudeMessageRequest{
		AnthropicVersion:  "bedrock-2023-05-31",
		MaxTokensToSample: 100,
		SystemPrompt:      "Respond what the user tells you.",
		Messages:          []ClaudeMessage{{Role: "user", Content: prompt}},
	})

	if err != nil {
		return "", errors.New("failed to marshal: " + err.Error())
	}

	output, err := m.BedrockRuntimeClient.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
		ModelId:     &m.ModelID,
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

// Helper function to execute signed HTTP requests to AWS
func (m *CustomBedrockClient) executeRequest(method, endpoint string, payload []byte, payloadHash string) ([]byte, error) {
	region := m.awsConfig.Region
	host := fmt.Sprintf("bedrock.%s.amazonaws.com", region)

	credentials, err := m.awsConfig.Credentials.Retrieve(context.Background())
	if err != nil {
		return nil, errors.New("Error retrieving credentials: " + err.Error())
	}

	req, err := http.NewRequest(method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("Error creating request: " + err.Error())
	}
	req.Host = host
	req.Header.Set("User-Agent", m.UserAgent)

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("Error reading response body: " + err.Error())
	}

	return body, nil
}
