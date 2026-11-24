package aws

import (
	"context"
	_ "embed"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

// lambdaUpdateWaitDuration bounds how long we wait for the function's
// LastUpdateStatus to return to Successful. UpdateFunctionConfiguration is
// asynchronous: without this wait, an immediate revert 409s with
// ResourceConflictException (an update is already in progress).
const lambdaUpdateWaitDuration = 2 * time.Minute

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.lambda-layer-extension",
		FriendlyName: "Add a Malicious Lambda Extension",
		Description: `
Establishes persistence by adding a malicious lambda extension.

Warm-up:

- Create a Lambda function and a lambda extension (layer)

Detonation:

- Add the extension as a layer to the Lambda function

References:

- https://www.clearvector.com/blog/lambda-spy/
`,
		Detection: `
Through CloudTrail's <code>UpdateFunctionConfiguration20150331v2</code> event.

While matching this event may be impractical and prone to false positives in most environments, the following can help to craft more precise detections:

- Identify calls to <code>UpdateFunctionConfiguration20150331v2</code> where the <code>responseElements</code> field contains <code>layer</code>, indicating that the function's layers were modified
- Identify calls to <code>UpdateFunctionConfiguration20150331v2</code> where <code>responseElements.layers</code> includes a layer that's from a different AWS account.'
`,
		Platform:                   stratus.AWS,
		PrerequisitesTerraformCode: tf,
		IsIdempotent:               true,
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())
	lambdaExtensionLayerArn := params["lambda_extension_layer_arn"]
	lambdaArn := params["lambda_arn"]

	// Update the function configuration with our layer
	_, err := lambdaClient.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: &lambdaArn,
		Layers:       []string{lambdaExtensionLayerArn},
	})

	if err != nil {
		return errors.New("unable to update function configuration: " + err.Error())
	}

	if err := waitForFunctionUpdate(lambdaClient, lambdaArn, "during detonation"); err != nil {
		return err
	}

	log.Println("Added simulated malicious layer to Lambda function ", lambdaArn)
	return nil
}

// waitForFunctionUpdate blocks until the function's LastUpdateStatus is
// Successful again. GetFunction accepts a name, ARN or partial ARN; we always
// pass the full ARN from the Terraform outputs.
func waitForFunctionUpdate(lambdaClient *lambda.Client, functionArn string, phase string) error {
	waitContext, cancel := context.WithTimeout(context.Background(), lambdaUpdateWaitDuration)
	defer cancel()

	if err := lambda.NewFunctionUpdatedV2Waiter(lambdaClient).Wait(waitContext, &lambda.GetFunctionInput{
		FunctionName: &functionArn,
	}, lambdaUpdateWaitDuration); err != nil {
		return errors.New("unable to complete function configuration update "+phase+" for "+functionArn+": "+err.Error())
	}
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	lambdaArn := params["lambda_arn"]
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())

	// In case the detonation update is still settling when revert runs
	// (e.g. after a detonation wait timeout), let it finish first.
	if err := waitForFunctionUpdate(lambdaClient, lambdaArn, "before revert"); err != nil {
		return err
	}

	// Update the function configuration with an empty list of layers
	_, err := lambdaClient.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: &lambdaArn,
		Layers:       []string{},
	})

	if err != nil {
		return errors.New("unable to update function configuration: " + err.Error())
	}

	if err := waitForFunctionUpdate(lambdaClient, lambdaArn, "during revert"); err != nil {
		return err
	}

	log.Printf("Layers have been removed from the Lambda function %s\n", lambdaArn)
	return nil
}
