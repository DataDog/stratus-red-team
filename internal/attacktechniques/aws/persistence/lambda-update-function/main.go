package aws

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"io/ioutil"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.lambda-update-function",
		FriendlyName: "Update or modify Lambda Function Code",
		Description: `
Establishes persistence by updating a lambda function's code with malicious code.
A further use case could be updating the code to exfiltrate data.

Warm-up: 

- Create a Lambda function.

Detonation: 

- Update the Lambda function code.
`,
		Detection:                  `Through CloudTrail's <code>UpdateFunctionCode*</code> event.`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	functionName := params["lambda_function_name"]
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())
	zip := "UEsDBAoDAAAAABGy0lRE4o1NOwAAADsAAAAJAAAAbGFtYmRhLnB5ZGVmIGxhbWJkYV9oYW5kbGVyKGUsIGMpOgogICAgcHJpbnQoIlN0cmF0dXMgc2F5cyBoZWxsbyEiKQpQSwECPwMKAwAAAAARstJUROKNTTsAAAA7AAAACQAkAAAAAAAAACCApIEAAAAAbGFtYmRhLnB5CgAgAAAAAAABABgAAL0yTlCD2AEA6mNPUIPYAQC9Mk5Qg9gBUEsFBgAAAAABAAEAWwAAAGIAAAAAAA=="

	log.Println("Updating the Lambda function code for " + functionName)

	zipFile, _ := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(zip)))

	_, err := lambdaClient.UpdateFunctionCode(context.Background(), &lambda.UpdateFunctionCodeInput{
		FunctionName: &functionName,
		Publish:      true,
		ZipFile:      zipFile,
	})

	if err != nil {
		return errors.New(fmt.Sprintf("unable to update lambda code for: %s: ", functionName) + err.Error())
	}

	return nil
}

// revert to original unmodified lambda
func revert(params map[string]string) error {
	functionName := params["lambda_function_name"]
	bucketName := params["bucket_name"]
	bucketKey := params["bucket_object_key"]
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Reverting the Lambda function code for " + functionName)

	_, err := lambdaClient.UpdateFunctionCode(context.Background(), &lambda.UpdateFunctionCodeInput{
		FunctionName: &functionName,
		Publish:      true,
		S3Bucket:     &bucketName,
		S3Key:        &bucketKey,
	})

	if err != nil {
		return errors.New(fmt.Sprintf("unable to revert lambda code for: %s: ", params["lambda_function_name"]) + err.Error())
	}

	return nil
}
