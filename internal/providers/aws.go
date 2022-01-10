package providers

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"log"
)

var isAuthenticated = false
var hasDeterminedIfAuthenticated = false

func init() {
	/*aws, _ := config.LoadDefaultConfig(context.TODO())
	stsClient := sts.NewFromConfig(aws)
	_, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	isAuthenticated = err == nil*/
}

func GetAWSProvider() aws.Config {
	/*if !isAuthenticated {
		log.Fatal("You are not authenticated to AWS, or have not set your default AWS region.")
	}*/
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	return cfg
}
