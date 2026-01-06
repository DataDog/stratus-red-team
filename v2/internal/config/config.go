package config

import (
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

// Config is the root configuration structure
type Config struct {
	Kubernetes KubernetesConfig `yaml:"kubernetes"`
}

// LoadConfig loads configuration from file.
func LoadConfig() (*Config, error) {
	configPath := getConfigPath()
	if configPath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
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
