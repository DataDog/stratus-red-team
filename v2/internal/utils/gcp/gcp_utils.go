package gcp_utils

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	utils "github.com/datadog/stratus-red-team/v2/internal/utils"
	"golang.org/x/crypto/ssh"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"log"
	"os"
	"strings"
)

type SshKeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

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
// Note: no error is returned if the principal does not have a binding in the project's IAM policy
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

	// no reference to the principal in the project's IAM policy, we're good to go - nothing to do
	return nil
}

const DefaultFictitiousAttackerEmail = "stratusredteam@gmail.com"

func GetAttackerPrincipal() string {
	const UserPrefix = "user:"
	if attackerEmail := os.Getenv(utils.AttackerEmailEnvVarKey); attackerEmail != "" {
		return UserPrefix + strings.ToLower(attackerEmail)
	} else {
		return UserPrefix + DefaultFictitiousAttackerEmail
	}
}

// CreateRSAKeyPair generates a new RSA key pair
// the private key is encoded in PEM format
// the public key is encoded in OpenSSH format
func CreateSSHKeyPair() (SshKeyPair, error) {
	// generate key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return SshKeyPair{}, err
	}

	// validate private key
	err = key.Validate()
	if err != nil {
		return SshKeyPair{}, err
	}

	// create public key
	pubKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return SshKeyPair{}, err
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(pubKey)

	// encode key
	// get ASN.1 DER format
	privKeyDer := x509.MarshalPKCS1PrivateKey(key)

	// PEM block
	privKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privKeyDer,
	}
	privKey := pem.EncodeToMemory(&privKeyBlock)

	return SshKeyPair{privKey, pubKeyBytes}, nil
}

// InsertToMetadata insert item into metadata
func InsertToMetadata(md *compute.Metadata, key string, value string) {
	var found bool

	// find the presence of key (ssh-keys, windows-keys) in metadata
	for _, mdi := range md.Items {
		// if it exists, add it to existing key
		if mdi.Key == key {
			val := fmt.Sprintf("%s\n%s", *mdi.Value, value)
			mdi.Value = &val

			found = true
			break
		}
	}

	// if key (ssh-keys, windows-keys) is not exists, create it and add our key
	if !found {
		md.Items = append(md.Items, &compute.MetadataItems{
			Key:   key,
			Value: &value,
		})
	}
}
