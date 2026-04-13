package main

import (
	"context"
	"fmt"
	"log"
	"os"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------
// Configuration — replace these values with your own, then build.
// DO NOT commit real account IDs or role ARNs.
// ---------------------------------------------------------------

const (
	stateBucketRegion = "us-east-1"

	// Techniques to run. One AWS, one GCP.
	awsTechnique = "aws.defense-evasion.cloudtrail-stop"
	gcpTechnique = "gcp.defense-evasion.delete-logging-sink"
)

/*
This example demonstrates S3 remote state with attacks against multiple
cloud providers.

State (Terraform tfstate, technique lifecycle, outputs, variables) is stored
in an S3 bucket in one AWS account. Terraform warmup and detonation target
different accounts/projects entirely.

The state bucket credentials are passed explicitly via S3BackendConfig.
Target credentials come from the environment (env vars, gcloud auth, etc.).

See README.md for setup instructions.
*/
func main() {
	// The loader import disables log output for programmatic usage.
	// Re-enable it so we can see what's happening.
	log.SetOutput(os.Stderr)

	stateBucketName := os.Getenv("STATE_BUCKET_NAME")
	if stateBucketName == "" {
		fmt.Println("Set STATE_BUCKET_NAME to the S3 bucket for remote state")
		os.Exit(1)
	}

	// --- State bucket credentials (explicit) ---
	bucketAccessKey := os.Getenv("STATE_AWS_ACCESS_KEY_ID")
	bucketSecretKey := os.Getenv("STATE_AWS_SECRET_ACCESS_KEY")
	bucketSessionToken := os.Getenv("STATE_AWS_SESSION_TOKEN")
	if bucketAccessKey == "" || bucketSecretKey == "" {
		fmt.Println("Set STATE_AWS_ACCESS_KEY_ID, STATE_AWS_SECRET_ACCESS_KEY, and STATE_AWS_SESSION_TOKEN")
		fmt.Println("See README.md for instructions")
		os.Exit(1)
	}

	bucketCfg, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithRegion(stateBucketRegion),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(bucketAccessKey, bucketSecretKey, bucketSessionToken),
		),
	)
	if err != nil {
		log.Fatalf("Failed to build bucket AWS config: %v", err)
	}

	// Log the bucket identity for visibility
	bucketSts := sts.NewFromConfig(bucketCfg)
	bucketIdentity, err := bucketSts.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalf("Failed to verify bucket credentials: %v", err)
	}
	log.Printf("State bucket identity: %s", *bucketIdentity.Arn)

	s3Backend := stratusrunner.S3BackendConfig{
		BucketName: stateBucketName,
		Region:     stateBucketRegion,
		AWSConfig:  bucketCfg,
	}

	// --- Run AWS technique ---
	log.Println("=== AWS technique ===")
	runTechnique(awsTechnique, s3Backend)

	// --- Run GCP technique ---
	log.Println("=== GCP technique ===")
	runTechnique(gcpTechnique, s3Backend)
}

func runTechnique(techniqueID string, s3Backend stratusrunner.S3BackendConfig) {
	correlationID := uuid.New()
	log.Printf("Technique: %s (correlation: %s)", techniqueID, correlationID)

	ttp := stratus.GetRegistry().GetAttackTechniqueByName(techniqueID)
	if ttp == nil {
		log.Fatalf("Unknown technique: %s", techniqueID)
	}

	runner := stratusrunner.NewRunner(
		ttp,
		stratusrunner.StratusRunnerNoForce,
		stratusrunner.WithS3Backend(s3Backend),
		stratusrunner.WithCorrelationID(correlationID),
	)

	log.Println("Warming up (target credentials from environment)")
	_, err := runner.WarmUp()
	if err != nil {
		log.Fatalf("Warmup failed: %v", err)
	}
	log.Println("Warmup complete")

	fmt.Printf("Press enter to detonate %s\n", techniqueID)
	fmt.Scanln()

	log.Println("Detonating")
	err = runner.Detonate()
	if err != nil {
		log.Fatalf("Detonation failed: %v", err)
	}
	log.Println("Detonation complete")

	log.Println("Reverting")
	err = runner.Revert()
	if err != nil {
		log.Printf("Warning: revert failed: %v", err)
	}

	log.Println("Cleaning up")
	err = runner.CleanUp()
	if err != nil {
		log.Fatalf("Cleanup failed: %v", err)
	}
	log.Println("Done")
}
