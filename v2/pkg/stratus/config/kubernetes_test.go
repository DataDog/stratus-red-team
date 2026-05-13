package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestGetTechniquePodConfig(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		techniqueID string
		expected    K8sPodConfig
	}{
		{
			name: "default-tolerations-applied",
			yaml: `
kubernetes:
  default:
    pod:
      tolerations:
        - key: dedicated
          operator: Equal
          value: security
          effect: NoSchedule
`,
			techniqueID: "k8s.privilege-escalation.privileged-pod",
			expected: K8sPodConfig{
				Tolerations: []v1.Toleration{{
					Key:      "dedicated",
					Operator: v1.TolerationOpEqual,
					Value:    "security",
					Effect:   v1.TaintEffectNoSchedule,
				}},
			},
		},
		{
			name: "default-image-and-labels",
			yaml: `
kubernetes:
  default:
    pod:
      image: custom:latest
      labels:
        app: stratus
`,
			techniqueID: "k8s.privilege-escalation.privileged-pod",
			expected: K8sPodConfig{
				Image:  "custom:latest",
				Labels: map[string]string{"app": "stratus"},
			},
		},
		{
			name: "technique-override-merges-with-default",
			yaml: `
kubernetes:
  default:
    namespace: default-ns
    pod:
      image: default-image
      labels:
        app: stratus
      tolerations:
        - key: dedicated
          operator: Equal
          value: security
          effect: NoSchedule
  techniques:
    "k8s.test.technique":
      pod:
        image: override-image
`,
			techniqueID: "k8s.test.technique",
			expected: K8sPodConfig{
				Image:  "override-image",
				Labels: map[string]string{"app": "stratus"},
				Tolerations: []v1.Toleration{{
					Key:      "dedicated",
					Operator: v1.TolerationOpEqual,
					Value:    "security",
					Effect:   v1.TaintEffectNoSchedule,
				}},
			},
		},
		{
			name:        "no-config",
			yaml:        ``,
			techniqueID: "k8s.test.technique",
			expected:    K8sPodConfig{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestConfig(tc.yaml)
			actual := cfg.GetKubernetesConfig().GetTechniquePodConfig(tc.techniqueID)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
