package aws

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
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
Simulates an attacker enumerating Bedrock models and then invoking AI21 Labs Jurassic-2 Mid to run inference using the provided prompt. LLMjacking is an attack vector where attackers use stolen cloud credentials to run large language models, leading to unauthorized inference. This technique demonstrates how attackers can use Bedrock to run inference on Jurassic-2 Mid to generate responses to prompts.

Warm-up: None.

Detonation: 

- Perform <code>bedrock:ListFoundationModels</code> to enumerate foundation models that can be used in the current region.
- Perform <code>bedrock:GetFoundationModelAvailability</code> to retrieve the availability information of Jurassic-2 Mid.
- Perform <code>bedrock:ListFoundationModelAgreementOffers</code> to get the offer token to be included in the agreement request.
- Perform <code>bedrock:CreateFoundationModelAgreement</code> to request access to Jurassic-2 Mid via a Marketplace agreement offer.
- Perform <code>bedrock:PutFoundationModelEntitlement</code> to enable the entitlement for Jurassic-2 Mid, actually enabling access.
- Perform <code>bedrock:InvokeModel</code> to invoke Jurassic-2 Mid.

References:

- https://permiso.io/blog/exploiting-hosted-models
- https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/
- https://sysdig.com/blog/growing-dangers-of-llmjacking/
- https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf
`,
		Detection: `
Through CloudTrail's <code>ListFoundationModels</code>, <code>bedrock:GetFoundationModelAvailability</code>, <code>bedrock:ListFoundationModelAgreementOffers</code>, <code>bedrock:CreateFoundationModelAgreement</code>, <code>bedrock:PutFoundationModelEntitlement</code> and <code>InvokeModel</code> events. 
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

	log.Println("Listing foundation models in the current region")
	var models []types.FoundationModelSummary
	result, err := bedrockClient.ListFoundationModels(context.Background(), &bedrock.ListFoundationModelsInput{})

	if err != nil {
		return fmt.Errorf("couldn't list foundation models: %w", err)
	}
	models = result.ModelSummaries
	log.Println("The following foundation models can be used, after enabling access:")
	for _, modelSummary := range models {
		log.Println(*modelSummary.ModelId)
	}

	log.Println("Retrieving the availability information of AI21 Labs Jurassic-2 Mid")
	response, err := GetFoundationModelAvailability(awsConnection, "ai21.j2-mid-v1")
	if err != nil {
		return fmt.Errorf("unable to get model availability info: %w", err)
	}
	log.Println("Model availability information: ", response)

	log.Println("Listing agreement offers for AI21 Labs Jurassic-2 Mid")
	offerToken, err := ListFoundationModelAgreementOffers(awsConnection, "ai21.j2-mid-v1")
	if err != nil {
		return fmt.Errorf("unable to list agreement offers: %w", err)
	}
	log.Println("Offer token successfully retrieved")

	log.Println("Requesting acces to AI21 Labs Jurassic-2 Mid via a Marketplace agreement offer")
	_, err = CreateFoundationModelAgreement(awsConnection, "ai21.j2-mid-v1", offerToken)
	if err != nil {
		return fmt.Errorf("unable to create model agreement: %w", err)
	}
	log.Println("Succesfully created the model agreement")

	log.Println("Enabling the entitlement for AI21 Labs Jurassic-2 Mid")
	_, err = PutFoundationModelEntitlement(awsConnection, "ai21.j2-mid-v1")
	if err != nil {
		return fmt.Errorf("unable to put model entitlement: %w", err)
	}
	log.Println("Succesfully enabled the model entitlement")

	log.Println("Checking the availability of AI21 Labs Jurassic-2 Mid")
	CheckFoundationModelAvailability(awsConnection, "ai21.j2-mid-v1")

	log.Println("Invoking AI21 Labs Jurassic-2 Mid")
	wrapper := invokeModelWrapper{BedrockRuntimeClient: bedrockruntime.NewFromConfig(awsConnection)}
	prompt := "Are you Turing complete?"
	_, err = wrapper.InvokeModel(prompt)
	if err != nil {
		return fmt.Errorf("unable to invoke Bedrock model: %w", err)
	}
	log.Println("Successfully invoked Bedrock model")
	return nil
}

// GetFoundationModelAvailability retrieves model availability information.
// Note: At the time of writing, this function is not available in the AWS SDK for Go v2
func GetFoundationModelAvailability(cfg aws.Config, model string) (string, error) {
	region := cfg.Region

	host := fmt.Sprintf("bedrock.%s.amazonaws.com", region)
	endpoint := fmt.Sprintf("https://%s/foundation-model-availability/%s", host, model)

	credentials, err := cfg.Credentials.Retrieve(context.Background())
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

	return string(offerToken), nil
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

	payloadHash := calculateHash(string(jsonPayload))

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

	payloadHash := calculateHash(string(jsonPayload))

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

func CheckFoundationModelAvailability(sdkConfig aws.Config, model string) {
	response, err := GetFoundationModelAvailability(sdkConfig, model)
	if err != nil {
		fmt.Println("Error making API request:", err)
		return
	}
	fmt.Println("Response:", response)

	var availabilityResponse struct {
		AgreementAvailability struct {
			Status string `json:"status"`
		} `json:"agreementAvailability"`
	}

	if err := json.Unmarshal([]byte(response), &availabilityResponse); err != nil {
		fmt.Printf("Error unmarshalling response body: %v", err)
		return
	} else {
		fmt.Println("Agreement Availability Status:", availabilityResponse.AgreementAvailability.Status)
	}

	for availabilityResponse.AgreementAvailability.Status != "AVAILABLE" {
		fmt.Println("The agreement is not available yet, waiting for 10 seconds...")
		time.Sleep(10 * time.Second)

		response, err = GetFoundationModelAvailability(sdkConfig, model)
		if err != nil {
			fmt.Println("Error making API request:", err)
			break
		}
		fmt.Println("Response:", response)

		if err := json.Unmarshal([]byte(response), &availabilityResponse); err != nil {
			fmt.Printf("Error unmarshalling response body: %v", err)
			break
		}
	}

	if availabilityResponse.AgreementAvailability.Status == "AVAILABLE" {
		fmt.Println("The agreement is now available")
	}
}

func calculateHash(jsonPayload string) string {
	hash := sha256.New()
	hash.Write([]byte(jsonPayload))
	return hex.EncodeToString(hash.Sum(nil))
}

type invokeModelWrapper struct {
	BedrockRuntimeClient *bedrockruntime.Client
}

type jurassic2Request struct {
	Prompt      string  `json:"prompt"`
	MaxTokens   int     `json:"maxTokens,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
}

type jurassic2Response struct {
	Completions []completion `json:"completions"`
}
type completion struct {
	Data data `json:"data"`
}
type data struct {
	Text string `json:"text"`
}

func (wrapper invokeModelWrapper) InvokeModel(prompt string) (string, error) {
	modelId := "ai21.j2-mid-v1"

	body, err := json.Marshal(jurassic2Request{
		Prompt:      prompt,
		MaxTokens:   1, // Set to minimum to reduce costs
		Temperature: 0.5,
	})

	if err != nil {
		return "", errors.New("failed to marshal: " + err.Error())
	}

	output, err := wrapper.BedrockRuntimeClient.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(modelId),
		ContentType: aws.String("application/json"),
		Body:        body,
	})

	if err != nil {
		return "", errors.New("failed to invoke model: " + err.Error())
	}

	var response jurassic2Response
	if err := json.Unmarshal(output.Body, &response); err != nil {
		return "", errors.New("failed to unmarshal: " + err.Error())
	}

	return response.Completions[0].Data.Text, nil
}
