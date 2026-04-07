package state

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/config"
)

// S3BackendConfig holds the configuration for storing state in an S3 bucket.
type S3BackendConfig struct {
	BucketName string
	Region     string
	AWSConfig  aws.Config
	// KeyPrefix is prepended to all S3 object keys. Defaults to
	// "stratus/" if empty.
	KeyPrefix string
}

// S3StateManager stores technique state (lifecycle, outputs, variables) in S3 while keeping
// Terraform source files on the local filesystem. It also injects a backend.tf that points
// Terraform's own state at the same bucket.
type S3StateManager struct {
	config        S3BackendConfig
	s3Client      *s3.Client
	technique     *stratus.AttackTechnique
	rootDirectory string
	fileSystem    FileSystem
}

func NewS3StateManager(technique *stratus.AttackTechnique, cfg S3BackendConfig) *S3StateManager {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "stratus/"
	}

	homeDirectory, _ := os.UserHomeDir()
	sm := &S3StateManager{
		config:        cfg,
		s3Client:      s3.NewFromConfig(cfg.AWSConfig),
		technique:     technique,
		rootDirectory: filepath.Join(homeDirectory, config.StratusBaseDirectoryName),
		fileSystem:    &LocalFileSystem{},
	}
	sm.Initialize()
	return sm
}

func (m *S3StateManager) Initialize() {
	if !m.fileSystem.FileExists(m.rootDirectory) {
		log.Println("Creating " + m.rootDirectory + " as it doesn't exist yet")
		err := m.fileSystem.CreateDirectory(m.rootDirectory, 0744)
		if err != nil {
			panic("Unable to create persistent directory: " + err.Error())
		}
	}

	if !m.fileSystem.FileExists(m.techniqueDir()) {
		err := m.fileSystem.CreateDirectory(m.techniqueDir(), 0744)
		if err != nil {
			panic("Unable to create persistent directory: " + err.Error())
		}
	}
}

func (m *S3StateManager) GetRootDirectory() string {
	return m.rootDirectory
}

func (m *S3StateManager) ExtractTechnique() error {
	dir := m.techniqueDir()

	// Write main.tf (same as FileSystemStateManager)
	mainTf := filepath.Join(dir, StratusStateTerraformFileName)
	if err := m.fileSystem.WriteFile(mainTf, m.technique.PrerequisitesTerraformCode, 0644); err != nil {
		return err
	}

	// Write shared config.tf (same as FileSystemStateManager)
	configTf := filepath.Join(dir, "config.tf")
	if err := m.fileSystem.WriteFile(configTf, config.SharedTerraformConfigVariable, 0644); err != nil {
		return err
	}

	// Write backend.tf pointing Terraform state at the S3 bucket. Credentials are NOT written here,
	// they are passed via -backend-config flags during terraform init.
	backendTf := fmt.Sprintf(`terraform {
  backend "s3" {
    bucket = %q
    key    = %q
    region = %q
  }
}
`, m.config.BucketName, m.s3Key("terraform.tfstate"), m.config.Region)

	backendFile := filepath.Join(dir, "backend.tf")
	if err := m.fileSystem.WriteFile(backendFile, []byte(backendTf), 0644); err != nil {
		return err
	}

	return nil
}

func (m *S3StateManager) CleanupTechnique() error {
	// Delete S3 objects for this technique
	keys := []string{
		m.s3Key("state"),
		m.s3Key("outputs.json"),
		m.s3Key("variables.json"),
		m.s3Key("terraform.tfstate"),
	}
	for _, key := range keys {
		_, err := m.s3Client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: &m.config.BucketName,
			Key:    aws.String(key),
		})
		if err != nil {
			log.Printf("Warning: failed to delete s3://%s/%s: %v", m.config.BucketName, key, err)
		}
	}

	// Remove local technique directory
	return m.fileSystem.RemoveDirectory(m.techniqueDir())
}

func (m *S3StateManager) GetTechniqueState() stratus.AttackTechniqueState {
	data, err := m.s3Get(m.s3Key("state"))
	if err != nil {
		return ""
	}
	return stratus.AttackTechniqueState(data)
}

func (m *S3StateManager) SetTechniqueState(state stratus.AttackTechniqueState) error {
	return m.s3Put(m.s3Key("state"), []byte(state))
}

func (m *S3StateManager) GetTerraformOutputs() (map[string]string, error) {
	return m.getJSONMap(m.s3Key("outputs.json"))
}

func (m *S3StateManager) WriteTerraformOutputs(outputs map[string]string) error {
	return m.putJSONMap(m.s3Key("outputs.json"), outputs)
}

func (m *S3StateManager) GetTerraformVariables() (map[string]string, error) {
	return m.getJSONMap(m.s3Key("variables.json"))
}

func (m *S3StateManager) WriteTerraformVariables(variables map[string]string) error {
	return m.putJSONMap(m.s3Key("variables.json"), variables)
}

// BackendConfigs returns the -backend-config key=value pairs that the
// TerraformManager should pass during terraform init, containing the
// bucket credentials.
func (m *S3StateManager) BackendConfigs() map[string]string {
	creds, err := m.config.AWSConfig.Credentials.Retrieve(context.Background())
	if err != nil {
		log.Printf("Warning: unable to retrieve S3 backend credentials: %v", err)
		return nil
	}

	configs := map[string]string{
		"access_key": creds.AccessKeyID,
		"secret_key": creds.SecretAccessKey,
	}
	if creds.SessionToken != "" {
		configs["token"] = creds.SessionToken
	}
	return configs
}

// s3Key builds the full S3 object key for a technique artifact.
// Mirrors the local filesystem layout: {prefix}{technique-id}/{artifact}
func (m *S3StateManager) s3Key(artifact string) string {
	return m.config.KeyPrefix + m.technique.ID + "/" + artifact
}

func (m *S3StateManager) techniqueDir() string {
	return filepath.Join(m.rootDirectory, m.technique.ID)
}

func (m *S3StateManager) s3Get(key string) ([]byte, error) {
	result, err := m.s3Client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &m.config.BucketName,
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer result.Body.Close()
	return io.ReadAll(result.Body)
}

func (m *S3StateManager) s3Put(key string, data []byte) error {
	_, err := m.s3Client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &m.config.BucketName,
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	return err
}

func (m *S3StateManager) getJSONMap(key string) (map[string]string, error) {
	data, err := m.s3Get(key)
	if err != nil {
		// Object doesn't exist yet — return empty map (same behavior
		// as FileSystemStateManager when file doesn't exist)
		return make(map[string]string), nil
	}
	result := make(map[string]string)
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (m *S3StateManager) putJSONMap(key string, data map[string]string) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return m.s3Put(key, encoded)
}
