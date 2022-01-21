package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader" // Note: This import is needed
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	stratusrunner "github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"log"
)

/*
	This example registers, warms up, then detonates a custom attack technique.
*/

//go:embed prerequisites.tf
var myPrerequisitesTerraformCode []byte

func buildCustomAttackTechnique() *stratus.AttackTechnique {
	return &stratus.AttackTechnique{
		ID:                         "my-sample-attack-technique",
		Description:                "A sample AWS attack technique that creates an IAM user as a pre-requisite, and prints its ARN as a detonation",
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Execution},
		PrerequisitesTerraformCode: myPrerequisitesTerraformCode,
		Detonate:                   detonate,
	}
}

func detonate(params map[string]string) error {
	iamUserName := params["iam_user_name"]
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())

	userResponse, err := iamClient.GetUser(context.Background(), &iam.GetUserInput{
		UserName: aws.String(iamUserName),
	})

	if err != nil {
		return errors.New("unable to retrieve IAM user information: " + err.Error())
	}

	log.Println("The ARN of our IAM user is: " + *userResponse.User.Arn)
	return nil
}

func main() {
	customTtpDefinition := buildCustomAttackTechnique()
	stratus.GetRegistry().RegisterAttackTechnique(customTtpDefinition)

	stratusRunner := stratusrunner.NewRunner(customTtpDefinition, stratusrunner.StratusRunnerNoForce)
	_, err := stratusRunner.WarmUp()
	defer stratusRunner.CleanUp()
	if err != nil {
		fmt.Println("Could not warm up TTP: " + err.Error())
		return
	}
	fmt.Println("TTP is warm! Press enter to detonate it")
	fmt.Scanln()
	err = stratusRunner.Detonate()
	if err != nil {
		fmt.Println("Could not detonate TTP: " + err.Error())
	}
}
