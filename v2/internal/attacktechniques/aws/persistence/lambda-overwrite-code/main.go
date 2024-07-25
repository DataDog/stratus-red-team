package aws

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"io"
	"log"
	"strings"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.lambda-overwrite-code",
		FriendlyName: "Overwrite Lambda Function Code",
		Description: `
Establishes persistence by overwriting a Lambda function's code. 
A further, more advanced, use-case could be updating the code to exfiltrate the data processed by the Lambda function at runtime.

Warm-up: 

- Create a Lambda function.

Detonation: 

- Update the Lambda function code.

References:

- https://research.splunk.com/cloud/aws_lambda_updatefunctioncode/
- Expel's AWS security mindmap
`,
		Detection: `
Through CloudTrail's <code>UpdateFunctionCode*</code> event, e.g. <code>UpdateFunctionCode20150331v2</code>.
`,
		Platform:                   stratus.AWS,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	functionName := params["lambda_function_name"]
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())
	zip := "UEsDBAoDAAAAABGy0lRE4o1NOwAAADsAAAAJAAAAbGFtYmRhLnB5ZGVmIGxhbWJkYV9oYW5kbGVyKGUsIGMpOgogICAgcHJpbnQoIlN0cmF0dXMgc2F5cyBoZWxsbyEiKQpQSwECPwMKAwAAAAARstJUROKNTTsAAAA7AAAACQAkAAAAAAAAACCApIEAAAAAbGFtYmRhLnB5CgAgAAAAAAABABgAAL0yTlCD2AEA6mNPUIPYAQC9Mk5Qg9gBUEsFBgAAAAABAAEAWwAAAGIAAAAAAA=="

	log.Println("Updating the code of Lambda function " + functionName)

	zipFile, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(zip)))
	if err != nil {
		return errors.New("unable to decode the payload to overwrite the code with: " + err.Error())
	}

	_, err = lambdaClient.UpdateFunctionCode(context.Background(), &lambda.UpdateFunctionCodeInput{
		FunctionName: &functionName,
		Publish:      true,
		ZipFile:      zipFile,
	})

	if err != nil {
		return fmt.Errorf("unable to update lambda code for %s: %w", functionName, err)
	}

	return nil
}

// revert to original unmodified lambda
func revert(params map[string]string, providers stratus.CloudProviders) error {
	functionName := params["lambda_function_name"]
	bucketName := params["bucket_name"]
	bucketKey := params["bucket_object_key"]
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())

	log.Println("Reverting the code of the Lambda function " + functionName)

	_, err := lambdaClient.UpdateFunctionCode(context.Background(), &lambda.UpdateFunctionCodeInput{
		FunctionName: &functionName,
		Publish:      true,
		S3Bucket:     &bucketName,
		S3Key:        &bucketKey,
	})

	if err != nil {
		return fmt.Errorf("unable to revert lambda code for %s: %w", functionName, err)
	}

	return nil
}
