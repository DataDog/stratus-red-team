package gcp

import (
	"context"
	_ "embed"
	"errors"
	"log"

	"encoding/base64"

	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	iam "google.golang.org/api/iam/v1"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.persistence.create-service-account-key",
		FriendlyName: "Create a GCP Service Account Key",
		Description: `
Establishes persistence by creating a service account key on an existing service account.

Warm-up:

- Create a service account

Detonation:

- Create a new key for the service account
`,
		Detection: `
Using GCP Admin Activity audit logs event <code>google.iam.admin.v1.CreateServiceAccountKey</code>.
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	saEmail := params["sa_email"]
	ctx := context.Background()
	service, err := iam.NewService(ctx, providers.GCP().GetUserAgentOption())
	if err != nil {
		return errors.New("Error instantiating GCP SDK Client: " + err.Error())
	}

	log.Println("Creating service account key on service account " + saEmail)
	resource := "projects/-/serviceAccounts/" + saEmail
	request := &iam.CreateServiceAccountKeyRequest{}
	key, err := service.Projects.ServiceAccounts.Keys.Create(resource, request).Do()
	if err != nil {
		return errors.New("Unable to create service account key: " + err.Error())
	}
	log.Println("Service account ley successfully created!")
	jsonKeyFile, _ := base64.StdEncoding.DecodeString(key.PrivateKeyData)

	log.Println("Service account key data: \n" + string(jsonKeyFile))

	return nil
}

func revert(params map[string]string) error {
	saEmail := params["sa_email"]
	resource := "projects/-/serviceAccounts/" + saEmail

	ctx := context.Background()
	service, err := iam.NewService(ctx, providers.GCP().GetUserAgentOption())
	if err != nil {
		return errors.New("")
	}

	keys, err := service.Projects.ServiceAccounts.Keys.List(resource).Do()
	if err != nil {
		return errors.New("Failed to list Service Account Keys: " + err.Error())
	}

	for _, key := range keys.Keys {
		if key.KeyType == "SYSTEM_MANAGED" {
			log.Println("Key is a SYSTEM_MANAGED key and won't be deleted: " + key.Name)
			continue
		}
		log.Println("Deleting service account key " + key.Name)
		_, err := service.Projects.ServiceAccounts.Keys.Delete(key.Name).Do()
		if err != nil {
			return errors.New("Failed to delete service account key: " + err.Error())
		}
	}

	return nil
}
