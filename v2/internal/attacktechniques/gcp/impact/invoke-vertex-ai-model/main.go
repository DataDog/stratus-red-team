package gcp

import (
	"context"
	"fmt"
	"log"
	"strings"

	"cloud.google.com/go/vertexai/genai"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

// candidateModels is tried in order until one succeeds. Uses stable aliases
// (no version suffix) so GCP automatically resolves them to the current supported
// version — aliases don't have retirement dates, unlike pinned version IDs.
// Ordered cheapest first.
var candidateModels = []string{
	"gemini-2.5-flash-lite",
	"gemini-2.5-flash",
	"gemini-2.5-pro",
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.impact.invoke-vertex-ai-model",
		FriendlyName: "Invoke a Vertex AI Model",
		Description: `
Invokes a Gemini generative AI model via the Vertex AI API. This simulates
an attacker who has obtained access to a GCP service account and abuses it
to run large language model workloads, incurring unexpected costs for the
victim organization.

Prerequisites:

- AI Platform API enabled (gcloud services enable aiplatform.googleapis.com)

Detonation:

- Call the Vertex AI API to generate content using a Gemini model
  in the <code>us-central1</code> region

References:

- https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/inference
- https://cloud.google.com/vertex-ai/docs/reference/rest/v1/projects.locations.endpoints/generateContent
`,
		Detection: `
Identify unexpected Vertex AI model invocations by monitoring for
<code>google.cloud.aiplatform.v1.PredictionService.GenerateContent</code> events in
GCP Data Access audit logs, particularly from unexpected service accounts or at
unusual times/volumes.
`,
		Platform:           stratus.GCP,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Impact},
		Detonate:           detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	ctx := context.Background()

	client, err := genai.NewClient(ctx, projectId, "us-central1", gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create Vertex AI client: %w", err)
	}
	defer client.Close()

	for _, modelName := range candidateModels {
		log.Printf("Invoking Vertex AI model %s in project %s\n", modelName, projectId)
		resp, err := client.GenerativeModel(modelName).GenerateContent(
			ctx,
			genai.Text("Tell me a joke about cloud security."),
		)
		if err != nil {
			if isNotFound(err) {
				log.Printf("Model %s not available in this project, trying next\n", modelName)
				continue
			}
			return fmt.Errorf("failed to invoke Vertex AI model: %w", err)
		}

		if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
			return fmt.Errorf("received empty response from Vertex AI model %s", modelName)
		}

		log.Printf("Successfully invoked Vertex AI model %s. Response: %v\n",
			modelName, resp.Candidates[0].Content.Parts[0])
		return nil
	}

	return fmt.Errorf("no Vertex AI model available in project %s (tried: %s) — ensure the Vertex AI API is enabled",
		projectId, strings.Join(candidateModels, ", "))
}

// isNotFound returns true when the gRPC error indicates the model does not exist
// or is not accessible in this project.
func isNotFound(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "NOT_FOUND") ||
		strings.Contains(msg, "code = NotFound") ||
		strings.Contains(msg, "was not found")
}
