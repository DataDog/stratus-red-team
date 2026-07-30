package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSConfigTerraformVariables(t *testing.T) {
	cfg := newTestConfig(`
aws:
  default:
    prefix: "team-<% .CorrelationID %>-"
    tags:
      Environment: test
      ExecutionID: "<% .CorrelationID %>"
  techniques:
    "aws.test.technique":
      prefix: technique-
      tags:
        Environment: production
        Owner: security
`)

	actual := cfg.GetTerraformVariables(
		"aws.test.technique",
		SubstitutionVars{CorrelationID: "11111111-2222-3333-4444-555555555555"},
	)
	require.Contains(t, actual, "config")

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(actual["config"]), &parsed))
	assert.Equal(t, map[string]any{
		"aws": map[string]any{
			"prefix": "technique-",
			"tags": map[string]any{
				"Environment": "production",
				"ExecutionID": "11111111-2222-3333-4444-555555555555",
				"Owner":       "security",
			},
		},
	}, parsed)
}

func TestAWSConfigTechniqueOnly(t *testing.T) {
	cfg := newTestConfig(`
aws:
  techniques:
    "aws.test.technique":
      tags:
        Owner: security
`)

	actual := cfg.GetTerraformVariables("aws.test.technique", SubstitutionVars{})
	require.Contains(t, actual, "config")

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(actual["config"]), &parsed))
	assert.Equal(t, map[string]any{
		"aws": map[string]any{
			"tags": map[string]any{"Owner": "security"},
		},
	}, parsed)
}

func TestLoadConfigPreservesAWSTagKeyCase(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
aws:
  default:
    tags:
      CostCenter: security
      StratusCorrelationID: "<% .CorrelationID %>"
`), 0600))
	t.Setenv(ConfigEnvVar, configPath)

	cfg, err := LoadConfig()
	require.NoError(t, err)
	actual := cfg.GetTerraformVariables(
		"aws.test.technique",
		SubstitutionVars{CorrelationID: testCorrelationID},
	)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(actual["config"]), &parsed))
	assert.Equal(t, map[string]any{
		"aws": map[string]any{
			"tags": map[string]any{
				"CostCenter":           "security",
				"StratusCorrelationID": testCorrelationID,
			},
		},
	}, parsed)
}

func TestAWSConfigTechniqueOverrideDoesNotMutateDefaults(t *testing.T) {
	cfg := newTestConfig(`
aws:
  default:
    tags:
      Environment: test
  techniques:
    "aws.test.override":
      tags:
        Environment: production
`)

	override := cfg.aws.getMergedConfig("aws.test.override", SubstitutionVars{})
	defaults := cfg.aws.getMergedConfig("aws.test.other", SubstitutionVars{})

	assert.Equal(t, "production", override["tags"].(map[string]any)["Environment"])
	assert.Equal(t, "test", defaults["tags"].(map[string]any)["Environment"])
}
