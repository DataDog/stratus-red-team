package utils

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"log"
	"strings"
)

func GetCurrentAccountId(cfg aws.Config) (string, error) {
	stsClient := sts.NewFromConfig(cfg)
	result, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return *result.Account, nil
}

func AwsConfigFromCredentials(accessKeyId string, secretAccessKey string, sessionToken string) aws.Config {
	credentialsProvider := config.WithCredentialsProvider(
		credentials.NewStaticCredentialsProvider(accessKeyId, secretAccessKey, sessionToken),
	)
	cfg, err := config.LoadDefaultConfig(context.Background(), credentialsProvider)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	return cfg
}

func IsErrorDueToEBSEncryptionByDefault(err error) bool {
	if err == nil {
		return false
	}
	errorMessage := strings.ToLower(err.Error())

	// EBS snapshots
	// error: operation error EC2: ModifySnapshotAttribute, https response error StatusCode: 400, RequestID: 12f44aeb-7b3b-4488-ac46-a432d20cc7a9, api error OperationNotPermitted: Encrypted snapshots with EBS default key cannot be shared
	if strings.Contains(errorMessage, "operationnotpermitted") && strings.Contains(errorMessage, "ebs default key") {
		return true
	}

	// AMIs
	// error: operation error EC2: ModifyImageAttribute, https response error StatusCode: 400, RequestID: 85f85eff-4114-4861-a659-f9aeea48d78b, api error InvalidParameter: Snapshots encrypted with the AWS Managed CMK can't be shared. Specify another snapshot.
	if strings.Contains(errorMessage, "invalidparameter") && strings.Contains(errorMessage, "snapshots encrypted with the aws managed cmk") {
		return true
	}

	return false

}
