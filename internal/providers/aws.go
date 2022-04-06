package providers

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/google/uuid"
	"log"
)

var awsProvider = AWSProvider{
	UniqueCorrelationId: UniqueExecutionId,
}

func AWS() *AWSProvider {
	return &awsProvider
}

type AWSProvider struct {
	awsConfig           *aws.Config
	UniqueCorrelationId uuid.UUID // unique value injected in the user-agent, to differentiate Stratus Red Team executions
}

func (m *AWSProvider) GetConnection() aws.Config {
	if m.awsConfig == nil {
		cfg, err := config.LoadDefaultConfig(context.Background(), customUserAgentApiOptions(m.UniqueCorrelationId))
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

// Functions below are related to customization of the user-agent header
// Code mostly taken from https://github.com/aws/aws-sdk-go-v2/issues/1432

func customUserAgentApiOptions(uniqueCorrelationId uuid.UUID) config.LoadOptionsFunc {
	return config.WithAPIOptions(func() (v []func(stack *middleware.Stack) error) {
		v = append(v, func(stack *middleware.Stack) error {
			return stack.Build.Add(customUserAgentMiddleware(uniqueCorrelationId), middleware.After)
		})
		return v
	}())
}

func customUserAgentMiddleware(uniqueId uuid.UUID) middleware.BuildMiddleware {
	return middleware.BuildMiddlewareFunc("CustomerUserAgent", func(
		ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler,
	) (out middleware.BuildOutput, metadata middleware.Metadata, err error) {
		request, ok := input.Request.(*smithyhttp.Request)
		if !ok {
			return out, metadata, fmt.Errorf("unknown transport type %T", input.Request)
		}
		request.Header.Set("User-Agent", StratusUserAgent+"_"+uniqueId.String())

		return next.HandleBuild(ctx, input)
	})
}
