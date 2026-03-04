package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
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
		overrides   []string
		expected    map[string]string
	}{
		{
			name: "namespace",
			yaml: `
kubernetes:
  default:
    namespace: test-namespace
`,
			techniqueID: "",
			overrides:   []string{"kubernetes.namespace"},
			expected: map[string]string{
				"config": `{"kubernetes":{"namespace":"test-namespace"}}`,
			},
		},
		{
			name: "namespace-and-default-image",
			yaml: `
kubernetes:
  default:
    namespace: test-namespace
    pod:
      image: test-default-image
`,
			techniqueID: "",
			overrides:   []string{"kubernetes.namespace", "kubernetes.pod.image"},
			expected: map[string]string{
				"config": `{"kubernetes":{"namespace":"test-namespace","pod":{"image":"test-default-image"}}}`,
			},
		},
		{
			name: "namespace-and-override-image",
			yaml: `
kubernetes:
  default:
    namespace: test-namespace
    pod:
      image: test-default-image
  techniques:
    "k8s.tactic.procedure":
      pod:
        image: test-override-image
    "k8s.tactic.procedure-2":
      pod:
        image: test-override-image-2
`,
			techniqueID: "k8s.tactic.procedure",
			overrides:   []string{"kubernetes.namespace", "kubernetes.pod.image"},
			expected: map[string]string{
				"config": `{"kubernetes":{"namespace":"test-namespace","pod":{"image":"test-override-image"}}}`,
			},
		},
		{
			name: "overloaded-config",
			yaml: `
kubernetes:
  default:
    pod:
      image: test-default-image
      labels:
        test-label: test-label-value
  techniques:
    "k8s.tactic.procedure":
      pod:
        tolerations:
          - key: test-toleration
            operator: Equal
            value: test-toleration-value
            effect: NoSchedule
`,
			techniqueID: "k8s.tactic.procedure",
			overrides:   []string{"kubernetes.pod.tolerations"},
			expected: map[string]string{
				"config": `{"kubernetes":{"pod":{"tolerations":[{"effect":"NoSchedule","key":"test-toleration","operator":"Equal","value":"test-toleration-value"}]}}}`,
			},
		},
		{
			// Unset paths are omitted from the JSON entirely (Viper drops nil-valued keys).
			// Terraform uses optional(type, default) to fill in zero values for absent fields.
			name: "variable-not-present",
			yaml: `
kubernetes:
  default:
    namespace: test-namespace
`,
			techniqueID: "k8s.tactic.procedure",
			overrides:   []string{"kubernetes.namespace", "kubernetes.pod.image"},
			expected: map[string]string{
				"config": `{"kubernetes":{"namespace":"test-namespace"}}`,
			},
		},
		{
			// No config file at all: return nil so Terraform uses its variable default.
			name:        "no-config",
			yaml:        ``,
			techniqueID: "k8s.tactic.procedure",
			overrides:   []string{"kubernetes.namespace", "kubernetes.pod.image"},
			expected:    nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := newTestConfig(test.yaml)
			actual := cfg.GetTerraformVariables(test.techniqueID, test.overrides)
			assert.Equal(t, test.expected, actual)
		})
	}
}
