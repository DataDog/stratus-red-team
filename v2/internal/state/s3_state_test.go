package state

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/stretchr/testify/assert"
)

// isolateHome keeps these tests off the developer's real ~/.stratus-red-team, which
// NewS3StateManager and ExtractTechnique would otherwise create and delete in.
func isolateHome(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
}

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
	isolateHome(t)
	technique := &stratus.AttackTechnique{
		ID:                         "aws.test.technique",
		PrerequisitesTerraformCode: []byte("resource {}"),
	}

	sm := NewS3StateManager(technique, newTestS3Config())

	err := sm.ExtractTechnique()
	assert.Nil(t, err)

	// Verify backend.tf was written with correct bucket and key
	backendTf, err := sm.fileSystem.ReadFile(sm.workingDirectory() + "/backend.tf")
	assert.Nil(t, err)
	assert.Contains(t, string(backendTf), `bucket = "my-stratus-bucket"`)
	assert.Contains(t, string(backendTf), `key    = "stratus/aws.test.technique/terraform.tfstate"`)
	assert.Contains(t, string(backendTf), `region = "us-east-1"`)

	// Verify main.tf and config.tf were also written
	mainTf, err := sm.fileSystem.ReadFile(sm.workingDirectory() + "/main.tf")
	assert.Nil(t, err)
	assert.Equal(t, "resource {}", string(mainTf))

	configTf, err := sm.fileSystem.ReadFile(sm.workingDirectory() + "/config.tf")
	assert.Nil(t, err)
	assert.NotEmpty(t, configTf)

	// Check correlation.tf
	correlationTf, err := sm.fileSystem.ReadFile(sm.workingDirectory() + "/correlation.tf")
	assert.Nil(t, err)
	assert.Contains(t, string(correlationTf), `variable "correlation"`)
}

func TestS3StateManagerBackendConfigs(t *testing.T) {
	isolateHome(t)
	technique := &stratus.AttackTechnique{ID: "aws.test.technique"}
	sm := NewS3StateManager(technique, newTestS3Config())

	configs := sm.BackendConfigs()

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", configs["access_key"])
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", configs["secret_key"])
	assert.Equal(t, "test-session-token", configs["token"])
}

func TestS3StateManagerKeyPrefix(t *testing.T) {
	isolateHome(t)
	technique := &stratus.AttackTechnique{ID: "aws.test.technique"}

	// Default prefix
	sm := NewS3StateManager(technique, newTestS3Config())
	assert.Equal(t, "stratus/aws.test.technique/state", sm.s3Key("state"))

	// Custom prefix
	cfg := newTestS3Config()
	cfg.KeyPrefix = "custom/prefix/"
	sm2 := NewS3StateManager(technique, cfg)
	assert.Equal(t, "custom/prefix/aws.test.technique/state", sm2.s3Key("state"))
}

// The flat keys are the backward-compatibility contract and must not move; the nested keys
// are what lets concurrent executions keep separate Terraform state.
func TestS3StateManagerExecutionSubdirectory(t *testing.T) {
	isolateHome(t)
	technique := &stratus.AttackTechnique{ID: "aws.test.technique"}

	flat := NewS3StateManager(technique, newTestS3Config())
	assert.Equal(t, "stratus/aws.test.technique/state", flat.s3Key("state"))
	assert.Equal(t, "stratus/aws.test.technique/terraform.tfstate", flat.s3Key("terraform.tfstate"))

	nested := NewS3StateManager(technique, newTestS3Config(), WithExecutionSubdirectory("sandbox1"), WithReadOnlyState())
	assert.Equal(t, "stratus/aws.test.technique/sandbox1/state", nested.s3Key("state"))
	assert.Equal(t, "stratus/aws.test.technique/sandbox1/terraform.tfstate", nested.s3Key("terraform.tfstate"))
	assert.Equal(t, flat.workingDirectory()+"/sandbox1", nested.workingDirectory())

	// An unusable name must not escape the technique directory: it falls back to flat.
	unsafe := NewS3StateManager(technique, newTestS3Config(), WithExecutionSubdirectory("../elsewhere"))
	assert.Equal(t, "stratus/aws.test.technique/state", unsafe.s3Key("state"))
	assert.Equal(t, flat.workingDirectory(), unsafe.workingDirectory())
}

func TestS3StateManagerBackendConfigsWithoutSessionToken(t *testing.T) {
	isolateHome(t)
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

	configs := sm.BackendConfigs()

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", configs["access_key"])
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", configs["secret_key"])
	_, hasToken := configs["token"]
	assert.False(t, hasToken, "token should not be present when session token is empty")
}

func TestS3StateManagerDefaultState(t *testing.T) {
	isolateHome(t)
	technique := &stratus.AttackTechnique{ID: "aws.test.technique"}
	sm := NewS3StateManager(technique, newTestS3Config())

	// Before any state is set, GetTechniqueState should return empty
	// (S3 GetObject will fail, returning empty state — same as
	// FileSystemStateManager behavior)
	state := sm.GetTechniqueState()
	assert.Equal(t, stratus.AttackTechniqueState(""), state)
}
