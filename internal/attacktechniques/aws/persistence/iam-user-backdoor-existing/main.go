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
		ID:           "aws.persistence.backdoor-iam-user",
		FriendlyName: "Create an Access Key on an IAM User",
		Description: `
Establishes persistence by creating an access key on an existing IAM user.

Warm-up: Create the pre-requisite IAM user.

Detonation: Create the access key.
`,
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate: func(params map[string]string) error {
			iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
			userName := params["user_name"]
			log.Println("Creating access key on legit IAM user to simulate backdoor")
			result, err := iamClient.CreateAccessKey(context.Background(), &iam.CreateAccessKeyInput{
				UserName: aws.String(userName),
			})
			if err != nil {
				return err
			}
			log.Println("Successfully created access key " + *result.AccessKey.AccessKeyId)
			return nil
		},
		Revert: func(params map[string]string) error {
			iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
			userName := params["user_name"]
			log.Println("Removing access key from IAM user " + userName)
			result, err := iamClient.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{
				UserName: aws.String(userName),
			})
			if err != nil {
				return err
			}
			for i := range result.AccessKeyMetadata {
				accessKeyId := result.AccessKeyMetadata[i].AccessKeyId
				log.Println("Removing access key " + *accessKeyId)
				_, err := iamClient.DeleteAccessKey(context.Background(), &iam.DeleteAccessKeyInput{
					AccessKeyId: accessKeyId,
					UserName:    aws.String(userName),
				})
				if err != nil {
					log.Println("failed: " + err.Error())
				}
			}

			return nil
		},
	})
}
