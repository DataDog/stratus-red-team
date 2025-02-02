package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"google.golang.org/api/iterator"
)

//go:embed main.tf
var tf []byte

const codeBlock = "```"
const AttackTechniqueId = "gcp.credential-access.secretmanager-retrieve-secrets"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           AttackTechniqueId,
		FriendlyName: "Retrieve a High Number of Secret Manager secrets",
		Description: `
Retrieves a high number of Secret Manager secrets in a short timeframe, through the AccessSecretVersion API.

Warm-up: 

- Create multiple secrets in Secret Manager.

Detonation: 

- Enumerate the secrets through the ListSecrets API
- Retrieve each secret value, one by one through the AccessSecretVersion API

Detection:

Cloud Audit Logs will show a high number of AccessSecretVersion API calls, from a single IP address. AccessSecretVersion 
is considered a data access event, and will need to be explicitly enabled in the Cloud Audit Logs configuration to log "Data Read"
events for the Secret Manager API. For more information, see the GCP Secret Manager documentation: https://cloud.google.com/secret-manager/docs/audit-logging

` + codeBlock + `json hl_lines="18 20 25"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "requestMetadata": {
      "callerIp": "7.7.7.7",
      "callerSuppliedUserAgent": "stratus-red-team_4fbc5d44-9c4f-469f-a15b-0c85e6ad3241 grpc-go/1.70.0,gzip(gfe)",
      "requestAttributes": {
        "time": "2025-02-02T22:56:34.343726445Z",
        "auth": {}
      },
      "destinationAttributes": {}
    },
    "serviceName": "secretmanager.googleapis.com",
    "methodName": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
    "authorizationInfo": [
      {
        "permission": "secretmanager.versions.access",
        "granted": true,
        "resourceAttributes": {
          "service": "secretmanager.googleapis.com",
          "name": "projects/victim-project/secrets/stratus-red-team-retrieve-secret-8/versions/latest",
          "type": "secretmanager.googleapis.com/SecretVersion"
        },
        "permissionType": "DATA_READ"
      }
    ],
    "resourceName": "projects/victim-project/secrets/stratus-red-team-retrieve-secret-8/versions/latest",
    "request": {
      "name": "projects/victim-project/secrets/stratus-red-team-retrieve-secret-8/versions/latest",
      "@type": "type.googleapis.com/google.cloud.secretmanager.v1.AccessSecretVersionRequest"
    }
  },
  "insertId": "j5g83weee2ya",
  "resource": {
    "type": "audited_resource",
    "labels": {
      "method": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
      "project_id": "victim-project",
      "service": "secretmanager.googleapis.com"
    }
  }
}
` + codeBlock + `

References:

- https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-services/gcp-secrets-manager-enum.html

`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess},
		Detonate:                   detonate,
		Revert:                     revert,
		PrerequisitesTerraformCode: tf,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	gcp := providers.GCP()
	ctx := context.Background()

	secretClient, err := secretmanager.NewClient(ctx, gcp.Options())
	if err != nil {
		return fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	defer secretClient.Close()

	secretsIterator := secretClient.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%s", gcp.GetProjectId()),
		Filter: "labels.stratus-red-team:*",
	})

	for {
		secret, err := secretsIterator.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list secrets: %w", err)
		}

		log.Println("Retrieving value of secret " + secret.Name)
		result, err := secretClient.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
			Name: secret.Name + "/versions/latest",
		})
		if err != nil {
			return fmt.Errorf("failed to access secret version: %w", err)
		}
		_ = result
	}

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// No cleanup needed for this technique
	return nil
}
