package aws

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/bedrock/types"
)

const inferenceTypeInferenceProfile = types.InferenceType("INFERENCE_PROFILE")

// The models returned by ListFoundationModels for the Anthropic provider.
func foundationModelsFixture() []types.FoundationModelSummary {
	return []types.FoundationModelSummary{
		foundationModel("anthropic.claude-3-haiku-20240307-v1:0", types.FoundationModelLifecycleStatusLegacy, types.InferenceTypeOnDemand),
		foundationModel("anthropic.claude-3-haiku-20240307-v1:0:200k", types.FoundationModelLifecycleStatusActive, types.InferenceTypeProvisioned),
		foundationModel("anthropic.claude-opus-4-6-v1", types.FoundationModelLifecycleStatusActive, inferenceTypeInferenceProfile),
		foundationModel("anthropic.claude-instant-v1", types.FoundationModelLifecycleStatusActive, types.InferenceTypeOnDemand),
		foundationModel("anthropic.claude-sonnet-4-6", types.FoundationModelLifecycleStatusActive, inferenceTypeInferenceProfile),
		foundationModel("anthropic.claude-3-7-sonnet-20250219-v1:0", types.FoundationModelLifecycleStatusLegacy, inferenceTypeInferenceProfile),
		foundationModel("anthropic.claude-3-5-haiku-20241022-v1:0", types.FoundationModelLifecycleStatusActive, inferenceTypeInferenceProfile),
		foundationModel("anthropic.claude-haiku-4-5-20251001-v1:0", types.FoundationModelLifecycleStatusActive, inferenceTypeInferenceProfile),
	}
}

// The system-defined inference profiles returned by ListInferenceProfiles.
func inferenceProfilesFixture() []types.InferenceProfileSummary {
	return []types.InferenceProfileSummary{
		inferenceProfile("global.anthropic.claude-haiku-4-5-20251001-v1:0", types.InferenceProfileStatusActive,
			"anthropic.claude-haiku-4-5-20251001-v1:0"),
		inferenceProfile("eu.anthropic.claude-haiku-4-5-20251001-v1:0", types.InferenceProfileStatusActive,
			"anthropic.claude-haiku-4-5-20251001-v1:0", "anthropic.claude-haiku-4-5-20251001-v1:0"),
		inferenceProfile("eu.anthropic.claude-3-5-haiku-20241022-v1:0", types.InferenceProfileStatusActive,
			"anthropic.claude-3-5-haiku-20241022-v1:0"),
		inferenceProfile("eu.anthropic.claude-sonnet-4-6", types.InferenceProfileStatusActive,
			"anthropic.claude-sonnet-4-6"),
		inferenceProfile("global.anthropic.claude-opus-4-6-v1", types.InferenceProfileStatusActive,
			"anthropic.claude-opus-4-6-v1"),
		inferenceProfile("eu.anthropic.claude-opus-4-6-v1", types.InferenceProfileStatus("INACTIVE"),
			"anthropic.claude-opus-4-6-v1"),
	}
}

func foundationModel(modelID string, status types.FoundationModelLifecycleStatus, inferenceTypes ...types.InferenceType) types.FoundationModelSummary {
	return types.FoundationModelSummary{
		ModelId:                 aws.String(modelID),
		InferenceTypesSupported: inferenceTypes,
		ModelLifecycle:          &types.FoundationModelLifecycle{Status: status},
	}
}

func inferenceProfile(profileID string, status types.InferenceProfileStatus, modelIDs ...string) types.InferenceProfileSummary {
	profile := types.InferenceProfileSummary{
		InferenceProfileId: aws.String(profileID),
		Status:             status,
		Type:               types.InferenceProfileTypeSystemDefined,
	}
	for _, modelID := range modelIDs {
		profile.Models = append(profile.Models, types.InferenceProfileModel{
			ModelArn: aws.String("arn:aws:bedrock:::foundation-model/" + modelID),
		})
	}
	return profile
}

func findModel(t *testing.T, models []types.FoundationModelSummary, modelID string) types.FoundationModelSummary {
	t.Helper()
	for _, model := range models {
		if aws.ToString(model.ModelId) == modelID {
			return model
		}
	}
	t.Fatalf("model %s not found in fixture", modelID)
	return types.FoundationModelSummary{}
}

func TestBaseModelID(t *testing.T) {
	tests := map[string]string{
		"anthropic.claude-haiku-4-5-20251001-v1:0":        "anthropic.claude-haiku-4-5-20251001-v1:0",
		"us.anthropic.claude-haiku-4-5-20251001-v1:0":     "anthropic.claude-haiku-4-5-20251001-v1:0",
		"global.anthropic.claude-haiku-4-5-20251001-v1:0": "anthropic.claude-haiku-4-5-20251001-v1:0",
		"us-gov.anthropic.claude-opus-4-8":                "anthropic.claude-opus-4-8",
		"anthropic.claude-v2":                             "anthropic.claude-v2",
	}
	for input, want := range tests {
		if got := baseModelID(input); got != want {
			t.Errorf("baseModelID(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestModelVersion(t *testing.T) {
	tests := map[string][2]int{
		"anthropic.claude-haiku-4-5-20251001-v1:0":     {4, 5},
		"anthropic.claude-sonnet-4-6":                  {4, 6},
		"anthropic.claude-opus-4-6-v1":                 {4, 6},
		"anthropic.claude-sonnet-4-20250514-v1:0":      {4, 0},
		"anthropic.claude-3-5-haiku-20241022-v1:0":     {3, 5},
		"anthropic.claude-3-haiku-20240307-v1:0:200k":  {3, 0},
		"eu.anthropic.claude-3-7-sonnet-20250219-v1:0": {3, 7},
		"anthropic.claude-v2:1":                        {0, 0},
		"anthropic.claude-instant-v1":                  {0, 0},
		"anthropic.":                                   {0, 0},
		"":                                             {0, 0},
	}
	for input, want := range tests {
		if got := modelVersion(input); got != want {
			t.Errorf("modelVersion(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestModelFamilyTier(t *testing.T) {
	tests := map[string]int{
		"anthropic.claude-3-haiku-20240307-v1:0":    0,
		"anthropic.claude-haiku-4-5-20251001-v1:0":  0,
		"anthropic.claude-3-7-sonnet-20250219-v1:0": 1,
		"anthropic.claude-sonnet-4-6":               1,
		"anthropic.claude-opus-4-6-v1":              2,
		"anthropic.claude-instant-v1":               unknownModelFamilyTier,
		"anthropic.claude-v2:1":                     unknownModelFamilyTier,
	}
	for input, want := range tests {
		if got := modelFamilyTier(input); got != want {
			t.Errorf("modelFamilyTier(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestRankActiveAnthropicModels(t *testing.T) {
	var got []string
	for _, model := range rankActiveAnthropicModels(foundationModelsFixture()) {
		got = append(got, aws.ToString(model.ModelId))
	}
	want := []string{
		"anthropic.claude-haiku-4-5-20251001-v1:0",
		"anthropic.claude-3-5-haiku-20241022-v1:0",
		"anthropic.claude-3-haiku-20240307-v1:0:200k",
		"anthropic.claude-sonnet-4-6",
		"anthropic.claude-opus-4-6-v1",
		"anthropic.claude-instant-v1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rankActiveAnthropicModels() = %v, want %v", got, want)
	}
}

func TestRankActiveAnthropicModelsBreaksTiesByModelID(t *testing.T) {
	models := []types.FoundationModelSummary{
		foundationModel("anthropic.claude-haiku-4-5-20251001-v1:0:200k", types.FoundationModelLifecycleStatusActive),
		foundationModel("meta.llama3-8b-instruct-v1:0", types.FoundationModelLifecycleStatusActive),
		foundationModel("anthropic.claude-haiku-4-5-20251001-v1:0", types.FoundationModelLifecycleStatusActive),
	}
	var got []string
	for _, model := range rankActiveAnthropicModels(models) {
		got = append(got, aws.ToString(model.ModelId))
	}
	want := []string{
		"anthropic.claude-haiku-4-5-20251001-v1:0",
		"anthropic.claude-haiku-4-5-20251001-v1:0:200k",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rankActiveAnthropicModels() = %v, want %v", got, want)
	}
}

func TestResolveInvokeModelID(t *testing.T) {
	models, profiles := foundationModelsFixture(), inferenceProfilesFixture()
	tests := []struct {
		modelID   string
		wantID    string
		wantFound bool
		reason    string
	}{
		{"anthropic.claude-instant-v1", "anthropic.claude-instant-v1", true, "on-demand model is invoked with its base model ID"},
		{"anthropic.claude-haiku-4-5-20251001-v1:0", "eu.anthropic.claude-haiku-4-5-20251001-v1:0", true, "geographic profile is preferred over the global one listed first"},
		{"anthropic.claude-opus-4-6-v1", "global.anthropic.claude-opus-4-6-v1", true, "inactive geographic profile is ignored"},
		{"anthropic.claude-3-haiku-20240307-v1:0:200k", "", false, "provisioned-only model without profile is skipped"},
	}
	for _, test := range tests {
		gotID, gotFound := resolveInvokeModelID(findModel(t, models, test.modelID), profiles)
		if gotID != test.wantID || gotFound != test.wantFound {
			t.Errorf("%s: resolveInvokeModelID(%q) = (%q, %v), want (%q, %v)", test.reason, test.modelID, gotID, gotFound, test.wantID, test.wantFound)
		}
	}
}

func TestResolveInvokeModelIDPrefersOnDemandOverProfile(t *testing.T) {
	model := foundationModel("anthropic.claude-haiku-4-5-20251001-v1:0", types.FoundationModelLifecycleStatusActive,
		types.InferenceTypeOnDemand, inferenceTypeInferenceProfile)
	gotID, gotFound := resolveInvokeModelID(model, inferenceProfilesFixture())
	if gotID != aws.ToString(model.ModelId) || !gotFound {
		t.Errorf("resolveInvokeModelID() = (%q, %v), want (%q, true)", gotID, gotFound, aws.ToString(model.ModelId))
	}
}

func TestSelectModelCandidates(t *testing.T) {
	got := selectModelCandidates(foundationModelsFixture(), inferenceProfilesFixture(), maxModelAttempts)
	want := []bedrockModelCandidate{
		{ModelID: "anthropic.claude-haiku-4-5-20251001-v1:0", InvokeModelID: "eu.anthropic.claude-haiku-4-5-20251001-v1:0"},
		{ModelID: "anthropic.claude-3-5-haiku-20241022-v1:0", InvokeModelID: "eu.anthropic.claude-3-5-haiku-20241022-v1:0"},
		{ModelID: "anthropic.claude-sonnet-4-6", InvokeModelID: "eu.anthropic.claude-sonnet-4-6"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("selectModelCandidates() = %v, want %v", got, want)
	}
}

func TestSelectModelCandidatesWithoutUsableModel(t *testing.T) {
	got := selectModelCandidates(foundationModelsFixture()[:2], nil, maxModelAttempts)
	if len(got) != 0 {
		t.Errorf("selectModelCandidates() = %v, want no candidate", got)
	}
}

type endlessInferenceProfilePager struct {
	pages int
}

func (p *endlessInferenceProfilePager) ListInferenceProfiles(context.Context, *bedrock.ListInferenceProfilesInput, ...func(*bedrock.Options)) (*bedrock.ListInferenceProfilesOutput, error) {
	p.pages++
	return &bedrock.ListInferenceProfilesOutput{
		NextToken:                 aws.String("next-page"),
		InferenceProfileSummaries: inferenceProfilesFixture()[:1],
	}, nil
}

func TestListInferenceProfilesStopsAfterMaxPages(t *testing.T) {
	pager := &endlessInferenceProfilePager{}
	_, err := listInferenceProfiles(context.Background(), pager)
	if err == nil {
		t.Fatal("listInferenceProfiles() succeeded, want a page limit error")
	}
	if !strings.Contains(err.Error(), "more than") {
		t.Errorf("listInferenceProfiles() error = %v, want a page limit error", err)
	}
	if pager.pages != maxInferenceProfilePages {
		t.Errorf("fetched %d pages, want %d", pager.pages, maxInferenceProfilePages)
	}
}
