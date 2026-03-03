package config

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	// StratusBaseDirectoryName is the name of the directory where Stratus Red Team stores state and config
	StratusBaseDirectoryName = ".stratus-red-team"
	ConfigFileName           = "config.yaml"
	ConfigEnvVar             = "STRATUS_CONFIG_PATH"
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
	kubernetes *KubernetesConfigImpl
	v          *viper.Viper
}

var _ Config = &ConfigImpl{}

// LoadConfig loads configuration from file.
func LoadConfig() (Config, error) {
	v := viper.New()
	configPath := getConfigPath()
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	}
	return &ConfigImpl{kubernetes: &KubernetesConfigImpl{v: v}, v: v}, nil
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

	defaultPath := filepath.Join(homeDir, StratusBaseDirectoryName, ConfigFileName)
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
	return c.kubernetes
}

// buildMergedViper produces a Viper containing the merged technique config.
// Each provider populates its own subtree via populateViperOverride.
func (c *ConfigImpl) buildMergedViper(techniqueID string) *viper.Viper {
	v := viper.New()
	if c == nil || c.kubernetes == nil {
		return v
	}
	c.kubernetes.populateViperOverride(c.v, v, techniqueID)
	// Add here other providers config
	return v
}

// GetTerraformVariables returns a single "config" Terraform variable whose value is a JSON object
// built by looking up each dotted override path in the merged technique config.
// Returns nil if overrides is empty.
func (c *ConfigImpl) GetTerraformVariables(techniqueID string, overrides []string) map[string]string {
	if c == nil || len(overrides) == 0 {
		return nil
	}

	merged := c.buildMergedViper(techniqueID)
	output := viper.New()
	for _, path := range overrides {
		output.Set(path, merged.Get(path))
	}

	settings := output.AllSettings()
	if len(settings) == 0 {
		// Returning nil, otherwise it would return { "config": {} } and Terraform would complain
		// that the config doesn't contain the expected keys
		return nil
	}

	jsonBytes, err := json.Marshal(settings)
	if err != nil {
		log.Println("Error marshalling Terraform config variables: " + err.Error())
		return nil
	}

	return map[string]string{"config": string(jsonBytes)}
}
