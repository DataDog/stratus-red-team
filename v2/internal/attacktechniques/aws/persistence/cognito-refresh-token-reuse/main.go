package aws

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.cognito-refresh-token-reuse",
		FriendlyName: "Reuse an Amazon Cognito Refresh Token",
		Description: `
Establishes persistence by reusing a valid Amazon Cognito refresh token to obtain fresh access and ID tokens, without knowing the user's password or repeating the initial authentication flow. As long as the refresh token remains valid and has not been revoked, an attacker who has stolen it can keep minting new tokens.

Warm-up:

- Create a Cognito user pool and an app client with refresh tokens enabled
- Create a confirmed test user with a permanent password
- Obtain an initial refresh token for that user (simulating an attacker who has compromised a valid refresh token)

Detonation:

- Exchange the refresh token for new access and ID tokens by calling <code>cognito-idp:GetTokensFromRefreshToken</code>

Note: To avoid leaking secrets, the token values obtained during warm-up and detonation are never printed or persisted; only non-sensitive metadata indicating that the exchange succeeded is logged.

References:

- https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.A006.html
- https://aws.amazon.com/blogs/security/what-the-march-2026-threat-technique-catalog-update-means-for-your-aws-environment/
- https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetTokensFromRefreshToken.html
`,
		Detection: `
Through CloudTrail's <code>GetTokensFromRefreshToken</code> event, with <code>eventSource</code> <code>cognito-idp.amazonaws.com</code>. A refresh-token exchange that originates from an unexpected IP address, user agent, or geolocation, or that occurs after the user's credentials are believed to have been rotated, is especially suspicious.
`,
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Persistence},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "Account Manipulation: Cognito Refresh Token Abuse",
						ID:   "T1098.A006",
						URL:  "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.A006.html",
					},
				},
			},
		},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	userPoolId := params["user_pool_id"]
	clientId := params["client_id"]
	username := params["username"]
	password := params["password"]

	cognitoClient := cognitoidentityprovider.NewFromConfig(providers.AWS().GetConnection())

	// Warm-up step: obtain an initial refresh token for the victim user. This simulates an attacker
	// who has already compromised a valid refresh token; the initial authentication flow is not the
	// technique itself and is intentionally kept separate from the detonation below.
	log.Println("Obtaining an initial refresh token for the victim user " + username)
	refreshToken, err := obtainInitialRefreshToken(cognitoClient, userPoolId, clientId, username, password)
	if err != nil {
		return fmt.Errorf("unable to obtain an initial refresh token: %w", err)
	}

	// Detonation: reuse the refresh token to mint fresh access and ID tokens, without re-authenticating.
	log.Println("Reusing the refresh token to obtain fresh access and ID tokens by calling cognito-idp:GetTokensFromRefreshToken")
	result, err := cognitoClient.GetTokensFromRefreshToken(context.Background(), &cognitoidentityprovider.GetTokensFromRefreshTokenInput{
		ClientId:     aws.String(clientId),
		RefreshToken: aws.String(refreshToken),
	})
	if err != nil {
		return fmt.Errorf("unable to reuse the refresh token to obtain new tokens: %w", err)
	}
	if result.AuthenticationResult == nil || result.AuthenticationResult.AccessToken == nil {
		return errors.New("the refresh token exchange did not return an access token")
	}

	log.Println("Successfully reused the refresh token and obtained fresh access and ID tokens for user " + username)
	log.Println("The refresh token remains valid and can be reused to mint new tokens until it expires or is revoked")
	return nil
}

// obtainInitialRefreshToken authenticates the test user via the admin auth flow to retrieve a valid
// refresh token. This is part of the warm-up (setup) and is deliberately separate from the detonation.
func obtainInitialRefreshToken(client *cognitoidentityprovider.Client, userPoolId, clientId, username, password string) (string, error) {
	authResult, err := client.AdminInitiateAuth(context.Background(), &cognitoidentityprovider.AdminInitiateAuthInput{
		AuthFlow:   types.AuthFlowTypeAdminUserPasswordAuth,
		ClientId:   aws.String(clientId),
		UserPoolId: aws.String(userPoolId),
		AuthParameters: map[string]string{
			"USERNAME": username,
			"PASSWORD": password,
		},
	})
	if err != nil {
		return "", fmt.Errorf("admin-initiate-auth failed: %w", err)
	}
	if authResult.AuthenticationResult == nil || authResult.AuthenticationResult.RefreshToken == nil {
		return "", errors.New("no refresh token was returned by the initial authentication")
	}
	return *authResult.AuthenticationResult.RefreshToken, nil
}
