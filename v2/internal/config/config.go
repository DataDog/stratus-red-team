package config

import (
	"maps"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	// StratusStateDirectoryName is the name of the directory where Stratus Red Team stores state and config
	StratusStateDirectoryName = ".stratus-red-team"
	ConfigFileName            = "config.yaml"
	ConfigEnvVar              = "STRATUS_CONFIG_PATH"
)

// Config is the root configuration structure.
//
// It is used to override techniques specifications. It can set variables in Terraform, or be called
// directly in the technique code.
type Config interface {
	GetKubernetesConfig() KubernetesConfig
	GetTerraformVariables(techniqueID string, overrides []string) map[string]string
}

type ConfigImpl struct {
	Kubernetes KubernetesConfig `yaml:"kubernetes"`
}

var _ Config = &ConfigImpl{}

// LoadConfig loads configuration from file.
func LoadConfig() (Config, error) {
	configPath := getConfigPath()
	if configPath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config ConfigImpl
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// getConfigPath returns the path to the config file, checking:
// 1. STRATUS_CONFIG_PATH environment variable
// 2. ~/.stratus-red-team/config.yaml
// Returns empty string if no config file exists
func getConfigPath() string {
	// Check environment variable first
	if envPath := os.Getenv(ConfigEnvVar); envPath != "" {
		if fileExists(envPath) {
			return envPath
		}
	}

	// Check default location (same directory as state)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	defaultPath := filepath.Join(homeDir, StratusStateDirectoryName, ConfigFileName)
	if fileExists(defaultPath) {
		return defaultPath
	}

	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (c *ConfigImpl) GetKubernetesConfig() KubernetesConfig {
	return c.Kubernetes
}

/*
 * Terraform variables
 *
 * This section defines the types and functions to handle Terraform variables override.
 */

// Name of the Terraform variables. Must match the name in the Terraform code.
//
// This is for internal use to create a list of Terraform variables. All the other code uses string
// instead to avoid depending on an internal type.
type TerraformConfigVariable string

// GetTerraformVariables returns the Terraform variables to use for the given overrides.
func (c *ConfigImpl) GetTerraformVariables(techniqueID string, overrides []string) map[string]string {
	result := make(map[string]string)

	// Kubernetes and EKS variables
	kubernetesVariables := c.Kubernetes.GetTerraformVariables(techniqueID, toConfigVars(overrides))
	maps.Copy(result, kubernetesVariables)

	// If one day we add other platforms overrides, we will defined them here.

	return result
}

func toConfigVars(s []string) []TerraformConfigVariable {
	r := make([]TerraformConfigVariable, len(s))
	for i, v := range s {
		r[i] = TerraformConfigVariable(v)
	}
	return r
}

// FilterVariables returns only the requested variables from allVars.
// This is a provider-independent helper for filtering Terraform variables.
func FilterVariables(allVars map[string]string, requested []TerraformConfigVariable) map[string]string {
	if len(requested) == 0 {
		return allVars
	}
	result := make(map[string]string)
	for _, v := range requested {
		if val, ok := allVars[string(v)]; ok {
			result[string(v)] = val
		}
	}
	return result
}
