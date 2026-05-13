package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyDelimiter documents the "::" Viper key delimiter used package-wide.
// Paths are joined with keyDelimiter ("::"). Dotted technique IDs (e.g.
// "k8s.privilege-escalation.privileged-pod") and dotted annotation/label keys
// (e.g. "app.kubernetes.io/name") are each a single literal segment, not nested
// map levels.
func TestKeyDelimiter(t *testing.T) {
	v := newViper()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(`
kubernetes:
  techniques:
    "k8s.privilege-escalation.privileged-pod":
      pod:
        annotations:
          app.kubernetes.io/name: hello
`)))

	// Build a deep path through Viper whose 3rd and 6th segments contain dots.
	// With keyDelimiter == "::", neither dot is treated as a separator.
	path := strings.Join([]string{
		"kubernetes",
		"techniques",
		"k8s.privilege-escalation.privileged-pod",
		"pod",
		"annotations",
		"app.kubernetes.io/name",
	}, keyDelimiter)

	assert.Equal(t,
		"kubernetes::techniques::k8s.privilege-escalation.privileged-pod::pod::annotations::app.kubernetes.io/name",
		path,
		"sanity check: keyDelimiter joins literal segments without altering them")

	assert.Equal(t, "hello", v.GetString(path))
}

// newTestConfig builds a ConfigImpl from a YAML string, mirroring how LoadConfig
// works when reading from a file.
func newTestConfig(yamlStr string) *ConfigImpl {
	v := newViper()
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
			actual := cfg.GetTerraformVariables(tc.techniqueID, SubstitutionVars{})

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
