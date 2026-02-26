package aws

import (
	"context"
	_ "embed"
	"errors"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                         "my-sample-attack-technique",
		Description:                "A sample AWS attack technique that creates an IAM user as a prerequisite, and prints its ARN as a detonation",
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	iamUserName := params["iam_user_name"]
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())

	userResponse, err := iamClient.GetUser(context.Background(), &iam.GetUserInput{
		UserName: &iamUserName,
	})

	if err != nil {
		return errors.New("unable to retrieve IAM user information: " + err.Error())
	}

	log.Println("The ARN of our IAM user is: " + *userResponse.User.Arn)
	return nil
}
