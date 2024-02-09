package utils

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	backoff "github.com/cenkalti/backoff/v4"
	"io"
	"log"
	"strconv"
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

// S3 utils

func ListAllObjectVersions(s3Client *s3.Client, bucketName string) ([]s3types.ObjectIdentifier, error) {
	log.Println("Listing objects in bucket " + bucketName)
	var result []s3types.ObjectIdentifier
	objectVersions, err := s3Client.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: &bucketName})
	if err != nil {
		return nil, fmt.Errorf("unable to list bucket objects: %w", err)
	}
	for _, objectVersion := range objectVersions.Versions {
		result = append(result, s3types.ObjectIdentifier{Key: objectVersion.Key, VersionId: objectVersion.VersionId})
	}
	return result, nil
}

func DownloadAllObjects(client *s3.Client, bucketName string) error {
	downloader := manager.NewDownloader(client)
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: &bucketName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return fmt.Errorf("unable to list bucket objects: %w", err)
		}
		for _, obj := range page.Contents {
			buf := manager.NewWriteAtBuffer([]byte{})
			_, err := downloader.Download(context.Background(), buf, &s3.GetObjectInput{
				Bucket: &bucketName,
				Key:    obj.Key,
			})
			if err != nil {
				return fmt.Errorf("unable to download object %s: %w", *obj.Key, err)
			}
		}
	}
	log.Println("Successfully downloaded all objects from the bucket")

	return nil
}

func UploadFile(s3Client *s3.Client, bucketName string, filename string, contents io.Reader) error {
	_, err := s3Client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &bucketName,
		Key:    aws.String(filename),
		Body:   contents,
	})
	return err
}

// ec2 utils

// WaitForInstancesToRegisterInSSM waits for a set of instances to be registered in SSM
// may be slow (60+ seconds)
func WaitForInstancesToRegisterInSSM(ssmClient *ssm.Client, instanceIds []string) error {
	if len(instanceIds) == 1 {
		log.Println("Waiting for instance" + instanceIds[0] + " to show up in AWS SSM")
	} else {
		log.Println("Waiting for " + strconv.Itoa(len(instanceIds)) + " instances to show up in AWS SSM. This can take a few minutes.")
	}

	for {
		time.Sleep(1 * time.Second)
		result, err := ssmClient.DescribeInstanceInformation(context.Background(), &ssm.DescribeInstanceInformationInput{
			Filters: []ssmtypes.InstanceInformationStringFilter{
				{Key: aws.String("InstanceIds"), Values: instanceIds},
			},
		})

		if err != nil {
			return err
		}

		instances := result.InstanceInformationList
		if len(instances) < len(instanceIds) {
			// Not enough instances registered yet, continue waiting
			continue
		}

		// Checked that all instances are ready in SSM
		allInstancesOnline := true
		for _, instance := range instances {
			if instance.PingStatus != ssmtypes.PingStatusOnline {
				allInstancesOnline = false
				break
			}
		}

		if allInstancesOnline {
			// If that's the case, great!
			return nil
		}

		// Otherwise, keep waiting
	}
}

// utility function for a single instance
func WaitForInstanceToRegisterInSSM(ssmClient *ssm.Client, instanceId string) error {
	return WaitForInstancesToRegisterInSSM(ssmClient, []string{instanceId})
}
