package cmd

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/datadog/stratus-red-team/v2/internal/state"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/config"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
)

const (
	EnvVarStateBucket          = "STRATUS_STATE_BUCKET"
	EnvVarStateBucketRegion    = "STRATUS_STATE_BUCKET_REGION"
	EnvVarStateBucketProfile   = "STRATUS_STATE_BUCKET_PROFILE"
	EnvVarStateAWSAccessKeyID  = "STRATUS_STATE_AWS_ACCESS_KEY_ID"
	EnvVarStateAWSSecretKey    = "STRATUS_STATE_AWS_SECRET_ACCESS_KEY"
	EnvVarStateAWSSessionToken = "STRATUS_STATE_AWS_SESSION_TOKEN"
)

var (
	flagStateBucket       string
	flagStateBucketRegion string
)

// resolveS3BackendConfig builds an S3BackendConfig from flags, env vars, and the config file (in
// that priority order). Returns nil if no bucket is configured, meaning local state should be used.
func resolveS3BackendConfig() *state.S3BackendConfig {
	bucket := resolveStateBucket()
	if bucket == "" {
		return nil
	}

	region := resolveStateBucketRegion()
	if region == "" {
		log.Fatal("S3 state bucket is configured but no region is set. " +
			"Use --state-bucket-region, STRATUS_STATE_BUCKET_REGION, or state.region in config")
	}

	awsCfg := resolveStateBucketCredentials(region)

	cfg := &state.S3BackendConfig{
		BucketName: bucket,
		Region:     region,
		AWSConfig:  awsCfg,
	}

	ensureBucketExists(cfg)
	return cfg
}

// resolveStateBucket returns the bucket name from flag > env > config.
func resolveStateBucket() string {
	if flagStateBucket != "" {
		return flagStateBucket
	}
	if env := os.Getenv(EnvVarStateBucket); env != "" {
		return env
	}
	// Config file is loaded by the runner, but we need it here for
	// the bucket name. Load it independently.
	cfg := loadConfigForStateBucket()
	if cfg != "" {
		return cfg
	}
	return ""
}

// resolveStateBucketRegion returns the region from flag > env > config.
func resolveStateBucketRegion() string {
	if flagStateBucketRegion != "" {
		return flagStateBucketRegion
	}
	if env := os.Getenv(EnvVarStateBucketRegion); env != "" {
		return env
	}
	cfg := loadConfigForStateBucketRegion()
	if cfg != "" {
		return cfg
	}
	return ""
}

// resolveStateBucketCredentials builds an aws.Config for the state bucket.
// Priority: named profile > explicit static creds > default chain (with warning).
func resolveStateBucketCredentials(region string) aws.Config {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}

	if profile := os.Getenv(EnvVarStateBucketProfile); profile != "" {
		log.Printf("Using AWS profile %q for state bucket", profile)
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	} else if accessKey := os.Getenv(EnvVarStateAWSAccessKeyID); accessKey != "" {
		secretKey := os.Getenv(EnvVarStateAWSSecretKey)
		sessionToken := os.Getenv(EnvVarStateAWSSessionToken)
		log.Println("Using explicit credentials for state bucket")
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken),
		))
	} else {
		log.Println("Warning: no dedicated credentials for state bucket, using default credential chain (same as target account)")
	}

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		log.Fatalf("Unable to load AWS config for state bucket: %v", err)
	}
	return cfg
}

func ensureBucketExists(cfg *state.S3BackendConfig) {
	s3Client := s3.NewFromConfig(cfg.AWSConfig, func(o *s3.Options) {
		o.DisableLogOutputChecksumValidationSkipped = true
	})

	_, err := s3Client.HeadBucket(context.Background(), &s3.HeadBucketInput{
		Bucket: &cfg.BucketName,
	})
	if err == nil {
		return
	}

	log.Printf("Creating state bucket s3://%s in %s", cfg.BucketName, cfg.Region)
	createInput := &s3.CreateBucketInput{
		Bucket: &cfg.BucketName,
	}
	// LocationConstraint is required for all regions except us-east-1
	if cfg.Region != "us-east-1" {
		createInput.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(cfg.Region),
		}
	}

	_, err = s3Client.CreateBucket(context.Background(), createInput)
	if err != nil {
		log.Fatalf("Unable to create state bucket: %v", err)
	}

	// Enable versioning (recommended for Terraform S3 backend)
	_, err = s3Client.PutBucketVersioning(context.Background(), &s3.PutBucketVersioningInput{
		Bucket: &cfg.BucketName,
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: s3types.BucketVersioningStatusEnabled,
		},
	})
	if err != nil {
		log.Printf("Warning: bucket created but versioning could not be enabled: %v", err)
	}

	log.Printf("State bucket s3://%s created with versioning enabled", cfg.BucketName)
}

// loadConfigForStateBucket reads state.bucket from the config file.
func loadConfigForStateBucket() string {
	cfg, err := loadConfigQuiet()
	if err != nil || cfg == nil {
		return ""
	}
	return cfg.GetStateConfig().Bucket
}

// loadConfigForStateBucketRegion reads state.region from the config file.
func loadConfigForStateBucketRegion() string {
	cfg, err := loadConfigQuiet()
	if err != nil || cfg == nil {
		return ""
	}
	return cfg.GetStateConfig().Region
}

// loadConfigQuiet loads the config without fataling on error.
func loadConfigQuiet() (config.Config, error) {
	return config.LoadConfig()
}

// buildRunnerOptions returns the RunnerOptions for S3 remote state, or nil if local state is configured.
func buildRunnerOptions() []runner.RunnerOption {
	s3Cfg := resolveS3BackendConfig()
	if s3Cfg == nil {
		return nil
	}
	return []runner.RunnerOption{runner.WithS3Backend(*s3Cfg)}
}
