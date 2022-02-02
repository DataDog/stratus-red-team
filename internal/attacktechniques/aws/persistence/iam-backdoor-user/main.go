package aws

import (
	"context"
	_ "embed"
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
		ID:           "aws.persistence.iam-backdoor-user",
		FriendlyName: "Create an Access Key on an IAM User",
		Description: `
Establishes persistence by creating an access key on an existing IAM user.

Warm-up: 

- Create an IAM user.

Detonation: 

- Create an IAM access key on the user.
`,
		Detection: `
Through CloudTrail's <code>CreateAccessKey</code> event. This event can hardly be considered suspicious by itself, unless
correlated with other indicators.
'`,
		Platform:                   stratus.AWS,
		IsIdempotent:               false, // iam:CreateAccessKey can only be called twice (limit of 2 access keys per user)
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	userName := params["user_name"]

	log.Println("Creating access key on legit IAM user to simulate backdoor")
	result, err := iamClient.CreateAccessKey(context.Background(), &iam.CreateAccessKeyInput{
		UserName: &userName,
	})
	if err != nil {
		return err
	}

	log.Println("Successfully created access key " + *result.AccessKey.AccessKeyId)
	return nil
}

func revert(params map[string]string) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	userName := params["user_name"]

	log.Println("Removing access key from IAM user " + userName)
	result, err := iamClient.ListAccessKeys(context.Background(), &iam.ListAccessKeysInput{
		UserName: &userName,
	})
	if err != nil {
		return err
	}

	for i := range result.AccessKeyMetadata {
		accessKeyId := result.AccessKeyMetadata[i].AccessKeyId
		log.Println("Removing access key " + *accessKeyId)
		_, err := iamClient.DeleteAccessKey(context.Background(), &iam.DeleteAccessKeyInput{
			AccessKeyId: accessKeyId,
			UserName:    &userName,
		})
		if err != nil {
			log.Println("failed: " + err.Error())
		}
	}

	return nil
}
