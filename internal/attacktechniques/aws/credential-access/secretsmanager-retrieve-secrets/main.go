package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.credential-access.secretsmanager-retrieve-secrets",
		FriendlyName: "Retrieve a High Number of Secrets Manager secrets",
		Description: `
Retrieves a high number of Secrets Manager secrets, through secretsmanager:GetSecretValue.

Warm-up: 

- Create multiple secrets in Secrets Manager.

Detonation: 

- Enumerate the secrets through secretsmanager:ListSecrets
- Retrieve each secret value, one by one through secretsmanager:GetSecretValue
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.CredentialAccess},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string) error {
	cfg, _ := config.LoadDefaultConfig(context.Background())
	secretsManagerClient := secretsmanager.NewFromConfig(cfg)

	secretsResponse, err := secretsManagerClient.ListSecrets(context.Background(), &secretsmanager.ListSecretsInput{
		Filters: []types.Filter{
			{Key: types.FilterNameStringTypeTagKey, Values: []string{"StratusRedTeam"}},
		},
		MaxResults: 100,
	})

	if err != nil {
		return errors.New("unable to list SecretsManager secrets: " + err.Error())
	}

	for i := range secretsResponse.SecretList {
		secret := secretsResponse.SecretList[i]
		log.Println("Retrieving value of secret " + *secret.ARN)
		_, err := secretsManagerClient.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
			SecretId: secret.ARN,
		})

		if err != nil {
			return errors.New("unable to retrieve secret value: " + err.Error())
		}
	}

	return nil
}
