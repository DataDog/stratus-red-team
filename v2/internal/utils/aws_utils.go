package utils

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	backoff "github.com/cenkalti/backoff/v4"
	"log"
	"strings"
	"time"
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

// WaitForAndAssumeAWSRole waits for an AWS role to be assumable (due to eventual consistency)
// then sets a credentials provider that can be used to assume the role.
func WaitForAndAssumeAWSRole(awsConnection *aws.Config, roleArn string) error {
	assumeRoleProvider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(*awsConnection), roleArn)
	backoffStrategy := backoff.NewExponentialBackOff()
	backoffStrategy.InitialInterval = 1 * time.Second // try to assume the role after 1s
	backoffStrategy.Multiplier = 2                    // double the interval after each failed attempt
	backoffStrategy.MaxInterval = 10 * time.Second    // never wait more than 10s between attempts
	backoffStrategy.MaxElapsedTime = 1 * time.Minute  // stop trying after 1 minute
	err := backoff.Retry(func() error {
		_, err := assumeRoleProvider.Retrieve(context.Background())
		return err
	}, backoffStrategy)
	if err != nil {
		return fmt.Errorf("unable to assume role %s: %v", roleArn, err)
	}
	awsConnection.Credentials = aws.NewCredentialsCache(assumeRoleProvider)
	return nil
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
