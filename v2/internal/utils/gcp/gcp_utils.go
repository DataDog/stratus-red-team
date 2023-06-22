package gcp_utils

import (
	"context"
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"google.golang.org/api/cloudresourcemanager/v1"
	"log"
)

// GCPAssignProjectRole grants a project-wide role to a specific service account
// it works the same as 'gcloud projects add-iam-policy-binding':
// * Step 1: Read the project's IAM policy using [getIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy)
// * Step 2: Create a binding, or add the service account to an existing binding for the role to grant
// * Step 3: Update the project's IAM policy using [setIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy)
func GCPAssignProjectRole(gcp *providers.GCPProvider, principal string, roleToGrant string) error {
	resourceManager, err := cloudresourcemanager.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("unable to instantiate the GCP cloud resource manager: " + err.Error())
	}

	projectPolicy, err := resourceManager.Projects.GetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return err
	}
	var bindingFound = false
	for _, binding := range projectPolicy.Bindings {
		if binding.Role == roleToGrant {
			bindingFound = true
			log.Println("Adding the principal " + principal + " to an existing binding in the project's IAM policy to grant " + roleToGrant)
			binding.Members = append(binding.Members, principal)
		}
	}
	if !bindingFound {
		log.Println("Creating a new binding in the project's IAM policy to grant " + roleToGrant + " to " + principal)
		projectPolicy.Bindings = append(projectPolicy.Bindings, &cloudresourcemanager.Binding{
			Role:    roleToGrant,
			Members: []string{principal},
		})
	}

	_, err = resourceManager.Projects.SetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.SetIamPolicyRequest{
		Policy: projectPolicy,
	}).Do()

	if err != nil {
		return fmt.Errorf("Failed to update project IAM policy: " + err.Error())
	}
	return nil
}

// GCPUnassignProjectRole un-assigns a project-wide role to a specific service account
// it works the same as 'gcloud projects remove-iam-policy-binding':
// * Step 1: Read the project's IAM policy using [getIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy)
// * Step 2: Remove a binding, or remove the service account from an existing binding for the role to grant
// * Step 3: Update the project's IAM policy using [setIamPolicy](https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy)
// Notes: this functions assumes that the binding does exist, and will return an error if not
func GCPUnassignProjectRole(gcp *providers.GCPProvider, principal string, roleToRemove string) error {
	resourceManager, err := cloudresourcemanager.NewService(context.Background(), gcp.Options())
	if err != nil {
		return errors.New("unable to instantiate the GCP cloud resource manager: " + err.Error())
	}

	projectPolicy, err := resourceManager.Projects.GetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.GetIamPolicyRequest{}).Do()
	if err != nil {
		return errors.New("unable to retrieve the project's IAM policy: " + err.Error())
	}
	var bindingFound = false
	for _, binding := range projectPolicy.Bindings {
		if binding.Role == roleToRemove {
			index := utils.IndexOf(binding.Members, principal)
			if index > -1 {
				bindingFound = true
				binding.Members = utils.Remove(binding.Members, index)
			}
		}
	}
	if bindingFound {
		log.Println("Updating project's IAM policy to remove reference to the principal " + principal + " for role " + roleToRemove)
		_, err := resourceManager.Projects.SetIamPolicy(gcp.GetProjectId(), &cloudresourcemanager.SetIamPolicyRequest{
			Policy: projectPolicy,
		}).Do()
		if err != nil {
			return errors.New("failed to update project IAM policy: " + err.Error())
		}
		return nil
	}
	return errors.New("did not find reference to the principal " + principal + " in the project's IAM policy")
}
