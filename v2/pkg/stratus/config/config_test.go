package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestConfig builds a ConfigImpl from a YAML string, mirroring how LoadConfig
// works when reading from a file.
func newTestConfig(yamlStr string) *ConfigImpl {
	v := viper.New()
	v.SetConfigType("yaml")
	_ = v.ReadConfig(strings.NewReader(yamlStr))
	return &ConfigImpl{kubernetes: &KubernetesConfigImpl{v: v}, v: v}
}

func TestGetTerraformVariables(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		techniqueID string
		// expected is the unmarshalled "config" JSON value, or nil if no config.
		expected any
	}{
		{
			name: "defaults-only",
			yaml: `
kubernetes:
  default:
    namespace: test-namespace
    pod:
      image: test-image
`,
			techniqueID: "",
			expected: map[string]any{
				"kubernetes": map[string]any{
					"namespace": "test-namespace",
					"pod": map[string]any{
						"image": "test-image",
					},
				},
			},
		},
		{
			name: "technique-override-merges-with-defaults",
			yaml: `
kubernetes:
  default:
    namespace: test-namespace
    pod:
      image: default-image
      labels:
        app: stratus
  techniques:
    "k8s.tactic.procedure":
      pod:
        image: override-image
    "k8s.tactic.procedure-2":
      pod:
        image: override-image-2
`,
			techniqueID: "k8s.tactic.procedure",
			expected: map[string]any{
				"kubernetes": map[string]any{
					"namespace": "test-namespace",
					"pod": map[string]any{
						"image": "override-image",
						"labels": map[string]any{
							"app": "stratus",
						},
					},
				},
			},
		},
		{
			name: "unmatched-technique-gets-defaults",
			yaml: `
kubernetes:
  default:
    namespace: test-namespace
  techniques:
    "k8s.other.technique":
      pod:
        image: other-image
`,
			techniqueID: "k8s.tactic.procedure",
			expected: map[string]any{
				"kubernetes": map[string]any{
					"namespace": "test-namespace",
				},
			},
		},
		{
			name:        "no-config",
			yaml:        ``,
			techniqueID: "k8s.tactic.procedure",
			expected:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestConfig(tc.yaml)
			actual := cfg.GetTerraformVariables(tc.techniqueID)

			if tc.expected == nil {
				assert.Nil(t, actual)
				return
			}

			require.Contains(t, actual, "config")
			var parsed any
			require.NoError(t, json.Unmarshal([]byte(actual["config"]), &parsed))
			assert.Equal(t, tc.expected, parsed)
		})
	}
}
