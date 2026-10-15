package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/useragent"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

const EnvVarCustomModel = "STRATUS_RED_TEAM_BEDROCK_MODEL"
const maxModelAttempts = 3

// Thinking-by-default models spend the budget on a thinking block first, so a small budget yields no text at all
const invokeMaxTokens = 1024
const maxInferenceProfilePages = 10

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
Simulates an attacker enumerating Bedrock models and then invoking an Anthropic Claude model to run inference using an arbitrary prompt. LLMjacking is an attack vector where attackers use stolen cloud credentials to run large language models, leading to unauthorized inference.

Warm-up: None.

Detonation:

- Enumerate the Anthropic models of the current region and keep the active ones
- Try up to ` + strconv.Itoa(maxModelAttempts) + ` of them, cheapest first (Haiku before Sonnet before Opus, most recent version first), until one succeeds:
	- If the model is not enabled, enable it using <code>PutUseCaseForModelAccess</code>, <code>ListFoundationModelAgreementOffers</code>, <code>CreateFoundationModelAgreement</code> and <code>PutFoundationModelEntitlement</code>
	- Invoke the model, through an inference profile when it does not support on-demand invocation

This requires the <code>bedrock:ListFoundationModels</code> and <code>bedrock:ListInferenceProfiles</code> permissions in addition to those needed to enable models. When an inference profile is used, <code>bedrock:InvokeModel</code> must be allowed on the profile and on the model in each of its destination regions.

References:

- https://permiso.io/blog/exploiting-hosted-models
- https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/
- https://sysdig.com/blog/growing-dangers-of-llmjacking/
- https://www.lacework.com/blog/detecting-ai-resource-hijacking-with-composite-alerts
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf

!!! note

	This technique attempts to enable and invoke the selected Bedrock model. To do this, it creates a Bedrock use case request for Anthropic models with a fictitious company name, website and use-case:

	- Company Name: <code>` + bedrockUseCaseRequest.CompanyName + `</code>
	- Company Website: <code>` + bedrockUseCaseRequest.CompanyWebsite + `</code>
	- Intended Users: <code>` + bedrockUseCaseRequest.IntendedUsers + `</code>
	- Industry Option: <code>` + bedrockUseCaseRequest.IndustryOption + `</code>
	- Use Cases: <code>` + bedrockUseCaseRequest.UseCases + `</code>


	It is expected that this will cause AWS to automatically send you an email entitled <code>You accepted an AWS Marketplace offer</code>. If you want to use a different Anthropic model, you can set the <code>` + EnvVarCustomModel + `</code> environment variable to the model ID or inference profile ID you want to use (see the list [here](https://docs.aws.amazon.com/bedrock/latest/userguide/model-cards-anthropic.html)). In that case, no model is selected dynamically: the model is enabled using its base model ID and invoked using the provided ID. Since the inputs to <code>InvokeModel</code> are model-specific, you can only specify an Anthropic model.


!!! note

	After enabling it, Stratus Red Team will not disable the Bedrock model.	While this should not incur any additional costs, you can disable the model by going to the [Model Access](https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/modelaccess) page in the AWS Management Console.
`,
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Impact},
		Detonate:           detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	awsConnection := providers.AWS().GetConnection()
	bedrockClient := CustomBedrockClient{
		BedrockClient:        bedrock.NewFromConfig(awsConnection),
		BedrockRuntimeClient: bedrockruntime.NewFromConfig(awsConnection),
		awsConfig:            awsConnection,
		UserAgent:            useragent.GetStratusUserAgentForUUID(providers.AWS().UniqueCorrelationId),
	}

	candidates, err := bedrockClient.findModelCandidates()
	if err != nil {
		return fmt.Errorf("unable to find a model to use: %w", err)
	}

	var failures []error
	for _, candidate := range candidates {
		bedrockClient.ModelID, bedrockClient.InvokeModelID = candidate.ModelID, candidate.InvokeModelID
		result, err := bedrockClient.enableAndInvokeModel()
		if err != nil {
			log.Println("Unable to use " + candidate.InvokeModelID + ": " + err.Error())
			failures = append(failures, fmt.Errorf("%s: %w", candidate.InvokeModelID, err))
			continue
		}
		log.Println("Successfully invoked Bedrock model. Response: " + result)
		return nil
	}
	return fmt.Errorf("unable to invoke any Bedrock model: %w", errors.Join(failures...))
}

func (m *CustomBedrockClient) enableAndInvokeModel() (string, error) {
	if err := m.EnsureModelEnabled(); err != nil {
		return "", err
	}
	log.Println("Invoking " + m.InvokeModelID)
	result, err := m.InvokeModel("Respond with: Hello, this is (your model) from Bedrock!")
	if err != nil {
		return "", fmt.Errorf("unable to invoke Bedrock model: %w", err)
	}
	return result, nil
}

type bedrockModelCandidate struct {
	ModelID       string
	InvokeModelID string
}

func (m *CustomBedrockClient) findModelCandidates() ([]bedrockModelCandidate, error) {
	if model := os.Getenv(EnvVarCustomModel); model != "" {
		return []bedrockModelCandidate{{ModelID: baseModelID(model), InvokeModelID: model}}, nil
	}

	log.Println("Listing Anthropic models available in " + m.awsConfig.Region)
	models, err := m.ListFoundationModels()
	if err != nil {
		return nil, err
	}
	profiles, err := m.ListInferenceProfiles()
	if err != nil {
		return nil, err
	}

	candidates := selectModelCandidates(models, profiles, maxModelAttempts)
	if len(candidates) == 0 {
		return nil, errors.New("no ACTIVE Anthropic model can be invoked in region " + m.awsConfig.Region)
	}
	return candidates, nil
}

// ListFoundationModels lists the Anthropic text models of the current region.
func (m *CustomBedrockClient) ListFoundationModels() ([]types.FoundationModelSummary, error) {
	result, err := m.BedrockClient.ListFoundationModels(context.Background(), &bedrock.ListFoundationModelsInput{
		ByProvider:       aws.String("Anthropic"),
		ByOutputModality: types.ModelModalityText,
	})
	if err != nil {
		return nil, fmt.Errorf("ListFoundationModels failed: %w", err)
	}
	return result.ModelSummaries, nil
}

// ListInferenceProfiles lists the system-defined inference profiles that can be used from the current region.
func (m *CustomBedrockClient) ListInferenceProfiles() ([]types.InferenceProfileSummary, error) {
	return listInferenceProfiles(context.Background(), m.BedrockClient)
}

func listInferenceProfiles(ctx context.Context, client bedrock.ListInferenceProfilesAPIClient) ([]types.InferenceProfileSummary, error) {
	paginator := bedrock.NewListInferenceProfilesPaginator(client, &bedrock.ListInferenceProfilesInput{
		TypeEquals: types.InferenceProfileTypeSystemDefined,
		MaxResults: aws.Int32(1000),
	})

	var profiles []types.InferenceProfileSummary
	for page := 0; paginator.HasMorePages(); page++ {
		if page >= maxInferenceProfilePages {
			return nil, fmt.Errorf("ListInferenceProfiles returned more than %d pages", maxInferenceProfilePages)
		}
		result, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListInferenceProfiles failed: %w", err)
		}
		profiles = append(profiles, result.InferenceProfileSummaries...)
	}
	return profiles, nil
}

func selectModelCandidates(models []types.FoundationModelSummary, profiles []types.InferenceProfileSummary, limit int) []bedrockModelCandidate {
	var candidates []bedrockModelCandidate
	for _, model := range rankActiveAnthropicModels(models) {
		if len(candidates) >= limit {
			break
		}
		modelID := aws.ToString(model.ModelId)
		if invokeModelID, ok := resolveInvokeModelID(model, profiles); ok {
			candidates = append(candidates, bedrockModelCandidate{ModelID: modelID, InvokeModelID: invokeModelID})
		}
	}
	return candidates
}

// The Bedrock API exposes no prices, so models are ranked by family (cheapest first), then newest version first
func rankActiveAnthropicModels(models []types.FoundationModelSummary) []types.FoundationModelSummary {
	var active []types.FoundationModelSummary
	for _, model := range models {
		if model.ModelLifecycle == nil ||
			model.ModelLifecycle.Status != types.FoundationModelLifecycleStatusActive ||
			!strings.HasPrefix(aws.ToString(model.ModelId), "anthropic.") {
			continue
		}
		active = append(active, model)
	}
	sort.SliceStable(active, func(i, j int) bool {
		return isCheaperModel(aws.ToString(active[i].ModelId), aws.ToString(active[j].ModelId))
	})
	return active
}

func isCheaperModel(a, b string) bool {
	if tierA, tierB := modelFamilyTier(a), modelFamilyTier(b); tierA != tierB {
		return tierA < tierB
	}
	versionA, versionB := modelVersion(a), modelVersion(b)
	if versionA[0] != versionB[0] {
		return versionA[0] > versionB[0]
	}
	if versionA[1] != versionB[1] {
		return versionA[1] > versionB[1]
	}
	return a < b
}

var modelFamilyTiers = map[string]int{"haiku": 0, "sonnet": 1, "opus": 2}

const unknownModelFamilyTier = 3

func modelFamilyTier(modelID string) int {
	for _, token := range modelNameTokens(modelID) {
		if tier, ok := modelFamilyTiers[token]; ok {
			return tier
		}
	}
	return unknownModelFamilyTier
}

// Version numbers are the short numeric tokens of the model name, longer ones are release dates such as 20251001
func modelVersion(modelID string) [2]int {
	var version [2]int
	found := 0
	for _, token := range modelNameTokens(modelID) {
		if found == len(version) {
			break
		}
		if len(token) > 2 || strings.Trim(token, "0123456789") != "" {
			continue
		}
		number, err := strconv.Atoi(token)
		if err != nil {
			continue
		}
		version[found] = number
		found++
	}
	return version
}

func modelNameTokens(modelID string) []string {
	name, _, _ := strings.Cut(strings.TrimPrefix(baseModelID(modelID), "anthropic."), ":")
	return strings.Split(name, "-")
}

func resolveInvokeModelID(model types.FoundationModelSummary, profiles []types.InferenceProfileSummary) (string, bool) {
	if slices.Contains(model.InferenceTypesSupported, types.InferenceTypeOnDemand) {
		return aws.ToString(model.ModelId), true
	}
	return findInferenceProfileID(aws.ToString(model.ModelId), profiles)
}

func findInferenceProfileID(modelID string, profiles []types.InferenceProfileSummary) (string, bool) {
	best := ""
	for _, profile := range profiles {
		if profile.Status != types.InferenceProfileStatusActive || !inferenceProfileTargetsModel(profile, modelID) {
			continue
		}
		profileID := aws.ToString(profile.InferenceProfileId)
		if best == "" || isPreferredInferenceProfile(profileID, best) {
			best = profileID
		}
	}
	return best, best != ""
}

// Geographic profiles (us., eu., ...) keep requests within the geography of the source region, unlike global ones
func isPreferredInferenceProfile(a, b string) bool {
	if globalA, globalB := strings.HasPrefix(a, "global."), strings.HasPrefix(b, "global."); globalA != globalB {
		return globalB
	}
	return a < b
}

func inferenceProfileTargetsModel(profile types.InferenceProfileSummary, modelID string) bool {
	for _, model := range profile.Models {
		if strings.HasSuffix(aws.ToString(model.ModelArn), ":foundation-model/"+modelID) {
			return true
		}
	}
	return false
}

// Model access APIs only accept base model IDs, so strip any inference profile prefix such as "us." or "global."
func baseModelID(modelID string) string {
	if i := strings.Index(modelID, "anthropic."); i > 0 {
		return modelID[i:]
	}
	return modelID
}

type CustomBedrockClient struct {
	ModelID              string
	InvokeModelID        string
	BedrockClient        *bedrock.Client
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

func (m *CustomBedrockClient) EnsureModelEnabled() error {
	log.Println("Retrieving model availability for " + m.ModelID)
	availability, err := m.BedrockClient.GetFoundationModelAvailability(context.Background(), &bedrock.GetFoundationModelAvailabilityInput{
		ModelId: aws.String(m.ModelID),
	})
	if err != nil {
		return fmt.Errorf("unable to get model availability info for %s: %w", m.ModelID, err)
	}
	if availability.RegionAvailability != types.RegionAvailabilityAvailable {
		return errors.New("Bedrock model " + m.ModelID + " is not available in the current region. Try setting AWS_REGION=us-east-1 instead")
	}
	if availability.EntitlementAvailability != types.EntitlementAvailabilityAvailable {
		if err := m.enableModel(availability.AgreementAvailability); err != nil {
			return fmt.Errorf("unable to enable model: %w", err)
		}
	}
	return nil
}

func (m *CustomBedrockClient) enableModel(agreement *types.AgreementAvailability) error {
	log.Println("Enabling model " + m.ModelID)

	// AgreementAvailability is account-wide (not region-specific). If a use-case was put for the model once in the account, it will be available in all regions, and we'll only need to call PutFoundationModelEntitlement in further region
	if agreement == nil || agreement.Status != types.AgreementStatusAvailable {
		if strings.HasPrefix(m.ModelID, "anthropic.") {
			if err := m.putUseCaseForModelAccess(); err != nil {
				return fmt.Errorf("unable to put use case for model access: %w", err)
			}
		}

		offerToken, err := m.listFoundationModelAgreementOffers()
		if err != nil {
			return fmt.Errorf("unable to list agreement offers: %w", err)
		}

		if err := m.createFoundationModelAgreement(offerToken); err != nil {
			return fmt.Errorf("unable to create model agreement: %w", err)
		}
	}

	if err := m.PutFoundationModelEntitlement(); err != nil {
		return fmt.Errorf("unable to put model entitlement: %w", err)
	}
	log.Println("Successfully enabled model, waiting for it to become available. This can take a few minutes.")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return m.waitForModelToBecomeAvailable(ctx)
}

func (m *CustomBedrockClient) putUseCaseForModelAccess() error {
	// The API expects the JSON use-case form base64-encoded in the formData member, which the SDK blob serialization does
	formData, err := json.Marshal(bedrockUseCaseRequest)
	if err != nil {
		return fmt.Errorf("unable to marshal use case request: %w", err)
	}
	_, err = m.BedrockClient.PutUseCaseForModelAccess(context.Background(), &bedrock.PutUseCaseForModelAccessInput{
		FormData: formData,
	})
	if err != nil {
		return fmt.Errorf("PutUseCaseForModelAccess failed: %w", err)
	}
	return nil
}

func (m *CustomBedrockClient) listFoundationModelAgreementOffers() (string, error) {
	result, err := m.BedrockClient.ListFoundationModelAgreementOffers(context.Background(), &bedrock.ListFoundationModelAgreementOffersInput{
		ModelId: aws.String(m.ModelID),
	})
	if err != nil {
		return "", fmt.Errorf("ListFoundationModelAgreementOffers failed: %w", err)
	}
	if len(result.Offers) == 0 || result.Offers[0].OfferToken == nil {
		return "", errors.New("no offers found")
	}
	return *result.Offers[0].OfferToken, nil
}

// createFoundationModelAgreement defines the subscription agreement in AWS Marketplace that requests access to the model.
func (m *CustomBedrockClient) createFoundationModelAgreement(offerToken string) error {
	_, err := m.BedrockClient.CreateFoundationModelAgreement(context.Background(), &bedrock.CreateFoundationModelAgreementInput{
		ModelId:    aws.String(m.ModelID),
		OfferToken: aws.String(offerToken),
	})
	if err != nil {
		return fmt.Errorf("CreateFoundationModelAgreement failed: %w", err)
	}
	return nil
}

// PutFoundationModelEntitlement enables the entitlement for the model.
// This operation is not available in the AWS SDK for Go v2, so the request is hand-signed
func (m *CustomBedrockClient) PutFoundationModelEntitlement() error {
	payload, err := json.Marshal(map[string]string{"modelId": m.ModelID})
	if err != nil {
		return fmt.Errorf("unable to marshal request: %w", err)
	}

	endpoint := fmt.Sprintf("https://bedrock.%s.amazonaws.com/foundation-model-entitlement", m.awsConfig.Region)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("unable to create request: %w", err)
	}
	req.Header.Set("User-Agent", m.UserAgent)

	credentials, err := m.awsConfig.Credentials.Retrieve(context.Background())
	if err != nil {
		return fmt.Errorf("unable to retrieve credentials: %w", err)
	}
	if err = v4.NewSigner().SignHTTP(context.Background(), credentials, req, utils.SHA256Hash(string(payload)), "bedrock", m.awsConfig.Region, time.Now()); err != nil {
		return fmt.Errorf("unable to sign request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to make request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("PutFoundationModelEntitlement failed: " + resp.Status)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func (m *CustomBedrockClient) waitForModelToBecomeAvailable(ctx context.Context) error {
	const RetryInterval = 10 * time.Second
	ticker := time.NewTicker(RetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			availability, err := m.BedrockClient.GetFoundationModelAvailability(ctx, &bedrock.GetFoundationModelAvailabilityInput{
				ModelId: aws.String(m.ModelID),
			})
			if err != nil {
				return fmt.Errorf("unable to get model availability info for %s: %w", m.ModelID, err)
			}
			if agreement := availability.AgreementAvailability; agreement != nil {
				if agreement.Status == types.AgreementStatusAvailable {
					log.Println("The model is now ready to use!")
					return nil
				}
				if agreement.ErrorMessage != nil && *agreement.ErrorMessage != "" {
					return fmt.Errorf("error enabling model: %s", *agreement.ErrorMessage)
				}
			}
			log.Println("The agreement is not available yet, retrying in " + RetryInterval.String())
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for model %s to become available", m.ModelID)
		}
	}
}

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
		MaxTokensToSample: invokeMaxTokens,
		SystemPrompt:      "Respond what the user tells you.",
		Messages:          []ClaudeMessage{{Role: "user", Content: prompt}},
	})

	if err != nil {
		return "", errors.New("failed to marshal: " + err.Error())
	}

	output, err := m.BedrockRuntimeClient.InvokeModel(context.Background(), &bedrockruntime.InvokeModelInput{
		ModelId:     &m.InvokeModelID,
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
	if len(claudeResponse.Content) == 0 {
		return "", errors.New("no content in the Bedrock response")
	}
	for _, content := range claudeResponse.Content {
		if content.Text != "" {
			return content.Text, nil
		}
	}
	return "", nil
}
