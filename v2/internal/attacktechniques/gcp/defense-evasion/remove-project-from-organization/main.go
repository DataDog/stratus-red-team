package gcp

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
)

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.defense-evasion.remove-project-from-organization",
		FriendlyName: "Attempt to Remove a GCP Project from its Organization",
		Description: `
Attempts to remove a GCP project from its parent organization by moving it to an
attacker-controlled organization via the Cloud Resource Manager API. Removing a project
from an organization would allow an attacker to operate outside of Organization Policy
constraints, disable org-level audit log sinks, and evade security controls applied at
the organization node.

The API call generates an Admin Activity audit log event regardless of whether it succeeds.
In most environments the calling identity will lack the
<code>resourcemanager.projects.move</code> permission, so the call is expected to return a
permission-denied error — which is logged and ignored.

Detonation:

- Read current project metadata via the Cloud Resource Manager API
- Attempt to move the project to a different organization, which would detach it from the
  current organization

References:

- https://cloud.google.com/resource-manager/docs/creating-managing-projects
- https://cloud.google.com/resource-manager/reference/rest/v3/projects/move
- https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1666.A002.html
`,
		Detection: `
Identify calls to <code>google.cloud.resourcemanager.v3.Projects.MoveProject</code> (v3 API)
or <code>cloudresourcemanager.googleapis.com/projects.move</code> (v1 API) in
GCP Admin Activity audit logs, especially where the request attempts to change the
project parent to a different organization. Unexpected move attempts on the project
resource should be treated as high-severity events.
`,
		Platform:           stratus.GCP,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Detonate:           detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	projectId := gcp.GetProjectId()
	ctx := context.Background()

	svc, err := cloudresourcemanager.NewService(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create Cloud Resource Manager client: %w", err)
	}

	log.Printf("Reading current project metadata for %s\n", projectId)
	project, err := svc.Projects.Get("projects/" + projectId).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to get project %s: %w", projectId, err)
	}
	log.Printf("Project %s is currently a child of %s\n", projectId, project.Parent)

	// Attempt to move the project to an attacker-controlled organization.
	// We use a well-known public GCP organization ID that we clearly do not control.
	// The request is syntactically valid, so GCP processes it and records an
	// Admin Activity audit log event before returning 403 Permission Denied.
	// A request with an empty or missing parent is rejected at validation time (400)
	// before the audit layer is reached, producing no log event.
	attackerOrgId := "organizations/1"
	log.Printf("Attempting to move project %s to %s\n", projectId, attackerOrgId)
	_, err = svc.Projects.Move("projects/"+projectId, &cloudresourcemanager.MoveProjectRequest{
		DestinationParent: attackerOrgId,
	}).Context(ctx).Do()
	if err != nil {
		var apiErr *googleapi.Error
		if errors.As(err, &apiErr) && (apiErr.Code == 403 || apiErr.Code == 404) {
			// 403 is the expected outcome: the identity lacks permission to move
			// the project to the target organization. The attempt is still recorded
			// in Admin Activity audit logs as projects.move.
			// 404 means the target org does not exist; GCP still logs the attempt.
			log.Printf("Move attempt returned error (expected): %v\n", err)
			log.Printf("The cloudresourcemanager.googleapis.com/projects.move audit log event was generated\n")
			return nil
		}
		return fmt.Errorf("unexpected error attempting to move project: %w", err)
	}

	log.Printf("Project %s was successfully moved to %s\n", projectId, attackerOrgId)
	return nil
}
