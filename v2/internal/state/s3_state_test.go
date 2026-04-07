package state

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/stretchr/testify/assert"
)

func newTestS3Config() S3BackendConfig {
	cfg := aws.Config{
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(
			"AKIAIOSFODNN7EXAMPLE",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"test-session-token",
		),
	}
	return S3BackendConfig{
		BucketName: "my-stratus-bucket",
		Region:     "us-east-1",
		AWSConfig:  cfg,
	}
}

func TestS3StateManagerExtractTechniqueWritesBackendTf(t *testing.T) {
	technique := &stratus.AttackTechnique{
		ID:                         "aws.test.technique",
		PrerequisitesTerraformCode: []byte("resource {}"),
	}

	sm := NewS3StateManager(technique, newTestS3Config())

	err := sm.ExtractTechnique()
	assert.Nil(t, err)
	defer sm.fileSystem.RemoveDirectory(sm.techniqueDir())

	// Verify backend.tf was written with correct bucket and key
	backendTf, err := sm.fileSystem.ReadFile(sm.techniqueDir() + "/backend.tf")
	assert.Nil(t, err)
	assert.Contains(t, string(backendTf), `bucket = "my-stratus-bucket"`)
	assert.Contains(t, string(backendTf), `key    = "stratus/aws.test.technique/terraform.tfstate"`)
	assert.Contains(t, string(backendTf), `region = "us-east-1"`)

	// Verify main.tf and config.tf were also written
	mainTf, err := sm.fileSystem.ReadFile(sm.techniqueDir() + "/main.tf")
	assert.Nil(t, err)
	assert.Equal(t, "resource {}", string(mainTf))

	configTf, err := sm.fileSystem.ReadFile(sm.techniqueDir() + "/config.tf")
	assert.Nil(t, err)
	assert.NotEmpty(t, configTf)
}

func TestS3StateManagerBackendConfigs(t *testing.T) {
	technique := &stratus.AttackTechnique{ID: "aws.test.technique"}
	sm := NewS3StateManager(technique, newTestS3Config())
	defer sm.fileSystem.RemoveDirectory(sm.techniqueDir())

	configs := sm.BackendConfigs()

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", configs["access_key"])
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", configs["secret_key"])
	assert.Equal(t, "test-session-token", configs["token"])
}

func TestS3StateManagerKeyPrefix(t *testing.T) {
	technique := &stratus.AttackTechnique{ID: "aws.test.technique"}

	// Default prefix
	sm := NewS3StateManager(technique, newTestS3Config())
	defer sm.fileSystem.RemoveDirectory(sm.techniqueDir())
	assert.Equal(t, "stratus/aws.test.technique/state", sm.s3Key("state"))

	// Custom prefix
	cfg := newTestS3Config()
	cfg.KeyPrefix = "custom/prefix/"
	sm2 := NewS3StateManager(technique, cfg)
	defer sm2.fileSystem.RemoveDirectory(sm2.techniqueDir())
	assert.Equal(t, "custom/prefix/aws.test.technique/state", sm2.s3Key("state"))
}

func TestS3StateManagerBackendConfigsWithoutSessionToken(t *testing.T) {
	cfg := aws.Config{
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(
			"AKIAIOSFODNN7EXAMPLE",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"", // no session token
		),
	}
	technique := &stratus.AttackTechnique{ID: "aws.test.technique"}
	sm := NewS3StateManager(technique, S3BackendConfig{
		BucketName: "bucket",
		Region:     "us-east-1",
		AWSConfig:  cfg,
	})
	defer sm.fileSystem.RemoveDirectory(sm.techniqueDir())

	configs := sm.BackendConfigs()

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", configs["access_key"])
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", configs["secret_key"])
	_, hasToken := configs["token"]
	assert.False(t, hasToken, "token should not be present when session token is empty")
}

func TestS3StateManagerDefaultState(t *testing.T) {
	technique := &stratus.AttackTechnique{ID: "aws.test.technique"}
	sm := NewS3StateManager(technique, newTestS3Config())
	defer sm.fileSystem.RemoveDirectory(sm.techniqueDir())

	// Before any state is set, GetTechniqueState should return empty
	// (S3 GetObject will fail, returning empty state — same as
	// FileSystemStateManager behavior)
	state := sm.GetTechniqueState()
	assert.Equal(t, stratus.AttackTechniqueState(""), state)
}

func TestS3BackendConfigCredentialsRetrievable(t *testing.T) {
	cfg := newTestS3Config()
	creds, err := cfg.AWSConfig.Credentials.Retrieve(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", creds.AccessKeyID)
}
