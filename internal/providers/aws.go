package providers

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
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

	// We make a sample API call to AWS to ensure the user is authenticated
	// Note: We use ec2:DescribeAccountAttributes as an arbitrary API call
	// instead of sts:GetCallerIdentity, to ensure an AWS region was properly set
	ec2Client := ec2.NewFromConfig(m.GetConnection())
	_, err := ec2Client.DescribeAccountAttributes(context.Background(), &ec2.DescribeAccountAttributesInput{})
	return err == nil
}
