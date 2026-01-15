package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
)

func TestGetTerraformVariables(t *testing.T) {
	// Objects used in tests
	tolerations := []v1.Toleration{
		{
			Key:      "test-toleration",
			Operator: "Equal",
			Value:    "test-toleration-value",
			Effect:   "NoSchedule",
		},
	}
	tolerationsJSON, err := marshalTolerations(tolerations)
	require.NoError(t, err)

	tests := []struct {
		name        string
		cfg         *ConfigImpl
		techniqueID string
		overrides   []string
		expected    map[string]string
	}{
		{
			name: "namespace",
			cfg: &ConfigImpl{
				Kubernetes: &KubernetesConfigImpl{
					Namespace: "test-namespace",
				},
			},
			techniqueID: "",
			overrides:   []string{"namespace"},
			expected: map[string]string{
				"namespace": "test-namespace",
			},
		},
		{
			name: "namespace-and-default-image",
			cfg: &ConfigImpl{
				Kubernetes: &KubernetesConfigImpl{
					Namespace: "test-namespace",
					Defaults: K8sPodConfig{
						Image: "test-default-image",
					},
				},
			},
			techniqueID: "",
			overrides:   []string{"namespace", "image"},
			expected: map[string]string{
				"namespace": "test-namespace",
				"image":     "test-default-image",
			},
		},
		{
			name: "namespace-and-override-image",
			cfg: &ConfigImpl{
				Kubernetes: &KubernetesConfigImpl{
					Namespace: "test-namespace",
					Defaults: K8sPodConfig{
						Image: "test-default-image",
					},
					Techniques: map[string]K8sPodConfig{
						"test-technique": {
							Image: "test-override-image",
						},
						"test-technique-2": {
							Image: "test-override-image-2",
						},
					},
				},
			},
			techniqueID: "test-technique",
			overrides:   []string{"namespace", "image"},
			expected: map[string]string{
				"namespace": "test-namespace",
				"image":     "test-override-image",
			},
		},
		{
			name: "overloaded-config",
			cfg: &ConfigImpl{
				Kubernetes: &KubernetesConfigImpl{
					Namespace: "test-namespace",
					Defaults: K8sPodConfig{
						Image: "test-default-image",
						Labels: map[string]string{
							"test-label": "test-label-value",
						},
					},
					Techniques: map[string]K8sPodConfig{
						"test-technique": {
							Tolerations: tolerations,
						},
					},
				},
			},
			techniqueID: "test-technique",
			overrides:   []string{"tolerations"},
			expected: map[string]string{
				"tolerations": string(tolerationsJSON),
			},
		},
		{
			name: "variable-not-present",
			cfg: &ConfigImpl{
				Kubernetes: &KubernetesConfigImpl{
					Namespace: "test-namespace",
				},
			},
			techniqueID: "test-technique",
			overrides:   []string{"namespace", "image"},
			expected: map[string]string{
				"namespace": "test-namespace",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.cfg.GetTerraformVariables(test.techniqueID, test.overrides)
			assert.Equal(t, test.expected, actual)
		})
	}
}
