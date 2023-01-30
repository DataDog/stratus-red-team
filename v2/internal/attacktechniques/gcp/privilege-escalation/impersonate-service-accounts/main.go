package gcp

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"google.golang.org/api/iamcredentials/v1"
	"log"
	"strconv"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "gcp.privilege-escalation.impersonate-service-accounts",
		FriendlyName: "Impersonate GCP Service Accounts",
		Description: `
Attempts to impersonate several GCP service accounts. Service account impersonation in GCP allows to retrieve
temporary credentials allowing to act as a service account.

Warm-up:

- Create 10 GCP service accounts
- Grant the current user <code>roles/iam.serviceAccountTokenCreator</code> on one of these service accounts

Detonation:

- Attempt to impersonate each of the service accounts
- One impersonation request will succeed, simulating a successful privilege escalation


!!! info

    GCP takes a few seconds to propagate the new <code>roles/iam.serviceAccountTokenCreator</code> role binding to the current user.

    It is recommended to first warm up this attack technique (<code>stratus warmup ...</code>), wait for 30 seconds, then detonate it.

References:

- https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/
- https://cloud.google.com/iam/docs/impersonating-service-accounts
`,
		Detection: `
Using GCP Admin Activity audit logs event <code>GenerateAccessToken</code>. 
To get this event, you need to [enable IAM audit logs for data access activity](https://cloud.google.com/iam/docs/audit-logging#enabling_audit_logging).
More specifically, you need to enable <code>DATA_READ</code> for your GCP project, e.g. using Terraform:

` + codeBlock + `hcl
data "google_client_config" "current" {}

resource "google_project_iam_audit_config" "audit" {
  project = data.google_client_config.current.project
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
  }
}
` + codeBlock + `

Sample successful event (shortened for clarity):

` + codeBlock + `json hl_lines="12 21"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "user@domain.tld",
      "principalSubject": "user:user@domain.tld"
    },
    "requestMetadata": {
      "callerIp": "(calling IP)",
    },
    "serviceName": "iamcredentials.googleapis.com",
    "methodName": "GenerateAccessToken",
    "authorizationInfo": [
      {
        "permission": "iam.serviceAccounts.getAccessToken",
        "granted": true,
        "resourceAttributes": {}
      }
    ],
    "request": {
      "name": "projects/-/serviceAccounts/impersonated-service-account@project-id.iam.gserviceaccount.com",
      "@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest"
    }
  },
  "resource": {
    "type": "service_account",
    "labels": {
      "unique_id": "105711361070066902665",
      "email_id": "impersonated-service-account@project-id.iam.gserviceaccount.com",
      "project_id": "project-id"
    }
  },
  "severity": "INFO",
  "logName": "projects/project-id/logs/cloudaudit.googleapis.com%2Fdata_access"
}
` + codeBlock + `


When impersonation fails, the generated event **does not contain** the identity of the caller, as explained in the
[GCP documentation](https://cloud.google.com/logging/docs/audit#user-id):

> Audit logging doesn't redact the caller's principal email address for any access that succeeds or for any write operation.
> For read-only operations that fail with a "permission denied" error, Audit Logging might redact the caller's principal 
> email address unless the caller is a service account.

Sample **unsuccessful** event (shortened for clarity):

` + codeBlock + `json hl_lines="5 6 13 38"
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "status": {
      "code": 7,
      "message": "PERMISSION_DENIED"
    },
    "authenticationInfo": {},
    "requestMetadata": {
      "callerIp": "(calling IP)"
    },
    "serviceName": "iamcredentials.googleapis.com",
    "methodName": "GenerateAccessToken",
    "authorizationInfo": [
      {
        "permission": "iam.serviceAccounts.getAccessToken",
        "resourceAttributes": {}
      }
    ],
    "resourceName": "projects/-/serviceAccounts/103566171230474107362",
    "request": {
      "@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest",
      "name": "projects/-/serviceAccounts/target-service-account@project-id.iam.gserviceaccount.com"
    },
    "metadata": {
      "identityDelegationChain": [
        "projects/-/serviceAccounts/target-service-account@project-id.iam.gserviceaccount.com"
      ]
    }
  },
  "resource": {
    "type": "service_account",
    "labels": {
      "email_id": "target-service-account@project-id.iam.gserviceaccount.com",
      "project_id": "project-id"
    }
  },
  "severity": "ERROR",
  "logName": "projects/project-id/logs/cloudaudit.googleapis.com%2Fdata_access"
}
` + codeBlock + `

Some detection strategies may include:

* Alerting on unsuccessful impersonation attempts
* Alerting when the same IP address / user-agent attempts to impersonate several service accounts in a 
short amount of time (successfully or not)
`,
		Platform:                   stratus.GCP,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	serviceAccountEmails := strings.Split(params["service_account_emails"], ",")
	numServiceAccounts := len(serviceAccountEmails)

	iamCredentialsClient, err := iamcredentials.NewService(context.Background(), providers.GCP().Options())
	if err != nil {
		return fmt.Errorf("unable to instantiate GCP IAM client: %v", err)
	}

	log.Println("Attempting to impersonate each of the " + strconv.Itoa(numServiceAccounts) + " service accounts")

	success := false
	for _, serviceAccountEmail := range serviceAccountEmails {
		accessToken, err := impersonateServiceAccount(iamCredentialsClient, serviceAccountEmail)
		if err != nil {
			if isPermissionDeniedError(err) {
				log.Println("Attempting to impersonate " + serviceAccountEmail + " yielded an 'access denied' error, as expected")
			} else {
				return fmt.Errorf("unexpected error while attempting to impersonate a service account: %v", err)
			}
		} else {
			log.Printf("Successfully retrieved an access token for %s: \n  %s\n", serviceAccountEmail, getPrintableAccessToken(accessToken))
			success = true
		}
	}

	if !success {
		log.Println("Note: None of the impersonation attempts succeeded. " +
			"It might take a few minutes for GCP to take the permissions into account; try again shortly!")
	}
	return nil
}

// Simulates the impersonation of a service account
func impersonateServiceAccount(iamCredentialsClient *iamcredentials.Service, serviceAccountEmail string) (string, error) {
	// see also: https://cloud.google.com/iam/docs/create-short-lived-credentials-direct#sa-credentials-oauth
	serviceAccountName := fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccountEmail)
	response, err := iamCredentialsClient.Projects.ServiceAccounts.GenerateAccessToken(serviceAccountName, &iamcredentials.GenerateAccessTokenRequest{
		Scope:    []string{"https://www.googleapis.com/auth/cloud-platform"},
		Lifetime: "43200s", // 12 hours, the maximum allowed lifetime
	}).Do()

	if err != nil {
		return "", err
	}

	return response.AccessToken, nil
}

// Checks if an error returned by `GenerateAccessToken` corresponds to an (expected) access denied error
func isPermissionDeniedError(err error) bool {
	errorMessage := strings.ToLower(err.Error())
	return strings.Contains(errorMessage, "403") && strings.Contains(errorMessage, "denied")
}

// For some reason, the access tokens are padded with dots, which isn't pretty to display
func getPrintableAccessToken(accessToken string) string {
	var i int
	for i = len(accessToken) - 1; accessToken[i] == '.'; i-- {
	}
	return accessToken[:i+1]
}
