package utils

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"log"
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
