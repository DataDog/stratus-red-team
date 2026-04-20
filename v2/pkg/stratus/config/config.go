package config

import (
	"encoding/json"
	"fmt"
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
	GetTerraformVariables(techniqueID string) map[string]string
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
		rawYAML, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := validateConfig(rawYAML); err != nil {
			return nil, err
		}

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

// GetTerraformVariables returns the full merged config (defaults + technique overrides)
// as a Terraform variable. The returned map contains a single key "config" whose value is
// a JSON object that Terraform can decode into its variable "config" type.
// Returns nil if no config is loaded.
func (c *ConfigImpl) GetTerraformVariables(techniqueID string) map[string]string {
	if c == nil {
		return nil
	}

	merged := c.buildMergedViper(techniqueID)
	settings := merged.AllSettings()
	if len(settings) == 0 {
		return nil
	}

	jsonBytes, err := json.Marshal(settings)
	if err != nil {
		log.Println("Error marshalling Terraform config variables: " + err.Error())
		return nil
	}

	return map[string]string{"config": string(jsonBytes)}
}
