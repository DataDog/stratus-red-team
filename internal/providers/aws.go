package providers

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"log"
)

var awsProvider = AWSProvider{}

func AWS() *AWSProvider {
	return &awsProvider
}

type AWSProvider struct {
	awsConfig *aws.Config
}

func (m *AWSProvider) GetConnection() aws.Config {
	if m.awsConfig == nil {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			log.Fatalf("unable to load AWS configuration, %v", err)
		}
		m.awsConfig = &cfg
	}

	return *m.awsConfig
}

func (m *AWSProvider) IsAuthenticatedAgainstAWS() bool {
	m.GetConnection()
	stsClient := sts.NewFromConfig(m.GetConnection())
	_, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	return err == nil
}
